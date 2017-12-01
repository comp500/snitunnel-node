/*eslint-disable no-console*/

const tls = require("tls");
const net = require("net");
const PcapWriter = require("node-pcap-writer");

const config = require("./config.json");
const options = {
	host: config.host,
	servername: config.servername,
	port: config.tlsPort,
	rejectUnauthorized: config.strictChecking || false
};

var removeSuffix = function(buffer) {
	var offset = 43;
	offset += buffer[offset] + 1; // session ID length
	offset += buffer.readUIntBE(offset, 2) + 2; // cipher suites length
	offset += buffer[offset] + 1; // compression methods length
	
	var extsLength = buffer.readUIntBE(offset, 2);
	offset += 2;
	var originalOffset = offset;
	
	while (offset < (originalOffset + extsLength)) {
		var extType = buffer.readUIntBE(offset, 2);
		offset += 2;
		var extLength = buffer.readUIntBE(offset, 2);
		offset += 2;
		if (extType == 0) {
			var suffix = ".google.com";
			var serverNameLength = buffer.readUIntBE(offset + 3, 2);
			var origString = buffer.toString("utf8", offset + 5, offset + 5 + serverNameLength);
			var newString = origString.replace(suffix, "");
			buffer.writeUIntBE(newString.length, offset + 3, 2);
			var preSlice = buffer.slice(0, offset + 5);
			var postSlice = buffer.slice(offset + 5 + serverNameLength, buffer.length);
			return {
				host: newString,
				buffer: Buffer.concat([preSlice, Buffer.from(newString), postSlice])
			};
			break;
		}
		offset += extLength;
	}
	return null;
};

var socketIdCounter = 0;

const server = net.createServer((tcpSocket) => {
	var socketId = socketIdCounter++;
	tcpSocket.once("data", function (data) {
		// var pcapWriter = new PcapWriter('./test.pcap', 1500, 105);
		var normal = removeSuffix(data);
		if (normal == null) {
			throw new Error("no SNI");
		}
		console.log(normal.host);
		// pcapWriter.writePacket(data, new Date());
		// pcapWriter.close();
		var destSocket = new net.Socket({fd: tcpSocket.fd});
		destSocket.connect(443, "159.203.57.164", function () {
			destSocket.write(normal.buffer);
			tcpSocket.pipe(destSocket);
			destSocket.pipe(tcpSocket);
		});

		destSocket.on("error", (err) => {
			console.log("Socket error, id", socketId);
			console.dir(err);
			// Clean up
			tcpSocket.end();
		});

		tcpSocket.on("error", (err) => {
			console.log("Socket error, id", socketId);
			console.dir(err);
			// Clean up
			destSocket.end();
		});
	});

	/*// Save socketId then increment counter
	var socketId = socketIdCounter++;

	console.log("[" + socketId + "]", "Connection received from " + tcpSocket.remoteAddress);

	var tlsSocket = tls.connect(options, () => {
		console.log("[" + socketId + "]", "Connected to TLS server at", tlsSocket.remoteAddress, tlsSocket.authorized ? "authorized" : "unauthorized");

		var cert = tlsSocket.getPeerCertificate();

		if (config.fingerprintList && config.fingerprintList.length > 0) {
			if (config.fingerprintList.indexOf(cert.fingerprint.toUpperCase()) == -1) {
				if (tlsSocket.authorized) {
					console.log("[" + socketId + "]", "Certificate not in fingerprint list");
				} else {
					console.log("[" + socketId + "]", "Authorization error:", tlsSocket.authorizationError);
				}

				console.log("[" + socketId + "]", "Certificate details:", JSON.stringify(cert.subject));
				console.log("[" + socketId + "]", "Certificate fingerprint:", cert.fingerprint);
				console.log("[" + socketId + "]", "If you trust the above certificate, copy it to the fingerprint list in config.json");

				tlsSocket.end();
				tcpSocket.end();
			} else {
				console.log("[" + socketId + "]", "Fingerprint verified:", cert.fingerprint);

				// Sync file descriptors, for some reason
				tlsSocket.fd = tcpSocket.fd;
				// Pipe TCP -> TLS
				tcpSocket.pipe(tlsSocket);
				// Pipe TLS -> TCP
				tlsSocket.pipe(tcpSocket);
			}
		} else {
			if (tlsSocket.authorized) {
				console.log("[" + socketId + "]", "Certificate not in fingerprint list, forwarding anyway as list is empty");
				console.log("[" + socketId + "]", "Certificate details:", JSON.stringify(cert.subject));
				console.log("[" + socketId + "]", "Certificate fingerprint:", cert.fingerprint);
				console.log("[" + socketId + "]", "If you trust the above certificate, copy it to the fingerprint list in config.json to ensure future security");

				// Sync file descriptors, for some reason
				tlsSocket.fd = tcpSocket.fd;
				// Pipe TCP -> TLS
				tcpSocket.pipe(tlsSocket);
				// Pipe TLS -> TCP
				tlsSocket.pipe(tcpSocket);
			} else {
				console.log("[" + socketId + "]", "Authorization error:", tlsSocket.authorizationError);
				console.log("[" + socketId + "]", "Certificate details:", JSON.stringify(cert.subject));
				console.log("[" + socketId + "]", "Certificate fingerprint:", cert.fingerprint);
				console.log("[" + socketId + "]", "If you trust the above certificate, copy it to the fingerprint list in config.json");

				tlsSocket.end();
				tcpSocket.end();
			}
		}
	});

	tlsSocket.on("error", (err) => {
		console.log("Socket error, id", socketId);
		console.dir(err);
		// Clean up
		tcpSocket.end();
	});

	tcpSocket.on("error", (err) => {
		console.log("Socket error, id", socketId);
		console.dir(err);
		// Clean up
		tlsSocket.end();
	});
	
	tcpSocket.on("end", () => {
		console.log("[" + socketId + "]", "Socket disconnected");
	});*/
});

server.on("error", (err) => {
	console.dir(err);
});

server.listen(443, () => {
	console.log("TCP server started, awaiting connections");
});
