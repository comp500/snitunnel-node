/*eslint-disable no-console*/

const tls = require("tls");
const net = require("net");

const config = require("./config.json");

var removeSuffix = function(buffer) {
	var suffix = ".google.com";
	var offset = 3;
	// decrease length
	var originalTotalLength = buffer.readUIntBE(offset, 2);
	buffer.writeUIntBE(originalTotalLength - suffix.length, offset, 2);
	// get to hello length
	offset += 3;
	var originalHelloLength = buffer.readUIntBE(offset, 3);
	buffer.writeUIntBE(originalHelloLength - suffix.length, offset, 3);

	// get to 43
	offset += 37;
	offset += buffer[offset] + 1; // session ID length
	offset += buffer.readUIntBE(offset, 2) + 2; // cipher suites length
	offset += buffer[offset] + 1; // compression methods length
	
	var extsLength = buffer.readUIntBE(offset, 2);
	// decrease length
	buffer.writeUIntBE(extsLength - suffix.length, offset, 2);
	offset += 2;
	var originalOffset = offset;
	
	while (offset < (originalOffset + extsLength)) {
		var extType = buffer.readUIntBE(offset, 2);
		offset += 2;
		var extLength = buffer.readUIntBE(offset, 2);
		if (extType == 0) {
			// decrease length
			buffer.writeUIntBE(extLength - suffix.length, offset, 2);
		}
		offset += 2;
		if (extType == 0) {
			// decrease length
			var serverNameListLength = buffer.readUIntBE(offset, 2);
			buffer.writeUIntBE(serverNameListLength - suffix.length, offset, 2);
			// get SNI length
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
	// Save socketId then increment counter
	var socketId = socketIdCounter++;

	console.log("[" + socketId + "]", "Connection received from " + tcpSocket.remoteAddress);

	tcpSocket.once("data", function (data) {
		var normal = removeSuffix(data);
		if (normal == null) {
			console.log("[" + socketId + "]", "Error in received ClientHello packet: no SNI server_name found");
			console.log("[" + socketId + "]", "Printing hex dump:");
			console.log(data.toString("hex"));
			tcpSocket.end();
			return;
		}

		console.log("[" + socketId + "]", "TLS ClientHello received, connecting client to server at " + normal.host);

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
});

server.on("error", (err) => {
	console.dir(err);
});

server.listen(443, () => {
	console.log("TCP server started, awaiting connections");
});
