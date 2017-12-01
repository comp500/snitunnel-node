const buffer = Buffer.from("1603010200010001fc0303575867536e47810eb4ea32fa1cd19d8b6acc2ad03d643b4cdd9b0643289fa8ff20ada750ea79d851d9b3916ec459c722c4352eef708c56e6b78dbc7b184a1e7628001ec02bc02fcca9cca8c02cc030c00ac009c013c01400330039002f0035000a010001950000000f000d00000a6d69746d2e776174636800170000ff01000100000a000a0008001d001700180019000b00020100002300781fe52d73bf517fd38991d8d2ea180716ce7cb04a6cb0dd8b9af33fd346ee1b265bf9a199c0978e3dce996397891c11b331629803613c42f7ce25a0aa8c3949987ebf9a0f0ffaaa27b5c6ed4c1ba46a3798a42da44cdbc3a98c9e60e20e5f44862ac60afb83607690d9efbf521c5601763e3fde32b9e6ed480010000e000c02683208687474702f312e31000500050100000000000d0018001604030503060308040805080604010501060102030201001500ae0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", "hex");

var parsed = {
	contentType: buffer[0],
	protocolVersion: {
		major: buffer[1],
		minor: buffer[2]
	},
	length: buffer.readUIntBE(3, 2),
	handshake: {
		handshakeType: buffer[5],
		handshakeLength: buffer.readUIntBE(6, 3),
		clientHello: {
			protocolVersion: {
				major: buffer[9],
				minor: buffer[10]
			},
			random: {
				unixTime: buffer.readUIntBE(11, 4),
				randomBytes: buffer.toString("hex", 15, 43)
			},
			sessionIDLength: buffer[44],
			sessionID: ""
		}
	}
};

var x = parsed.handshake.clientHello.sessionIDLength;

if (x > 0) {
	parsed.handshake.clientHello.sessionID = buffer.toString("hex", 45, 44 + x);
}

parsed.handshake.clientHello.cipherSuitesLength = buffer.readUIntBE();

console.dir(parsed, {depth: null});

const appendSuffix = function(buffer) {
	var offset = 43;
	console.log(buffer.toString("hex", offset, buffer[offset] + offset));
	offset += buffer[offset] + 1; // session ID length
	console.log(offset);
	console.log(buffer.toString("hex", offset, offset + 10));
	offset += buffer.readUIntBE(offset, 2) + 2; // cipher suites length
	console.log(offset);
	offset += buffer[offset] + 1; // compression methods length
	console.log(offset);
	
	var extsLength = buffer.readUIntBE(offset, 2);
	offset += 2;
	var originalOffset = offset;

	console.log(extsLength);
	console.log(offset);
	
	while (offset < (originalOffset + extsLength)) {
		var extType = buffer.readUIntBE(offset, 2);
		console.log(extType);
		offset += 2;
		var extLength = buffer.readUIntBE(offset, 2);
		offset += 2;
		if (extType == 0) {
			var suffix = ".google.com";
			var serverNameLength = buffer.readUIntBE(offset + 3, 2);
			var origString = buffer.toString("utf8", offset + 5, offset + 5 + serverNameLength);
			var newString = origString + suffix;
			buffer.writeUIntBE(newString.length, offset + 3, 2);
			var preSlice = buffer.slice(0, offset + 5);
			var postSlice = buffer.slice(offset + 5 + serverNameLength, buffer.length);
			return {
				host: origString,
				buffer: Buffer.concat([preSlice, Buffer.from(newString), postSlice])
			};
			break;
		}
		offset += extLength;
	}
	return null;
};

console.log(appendSuffix(buffer));

/*var appendSuffix = function(buffer) {
	var offset = 44;
	offset += buffer[offset]; // session ID length
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
			var newString = origString + suffix;
			buffer.writeUIntBE(newString.length, offset + 3, 2);
			var preSlice = buffer.slice(0, offset + 5);
			var postSlice = buffer.slice(offset + 5 + serverNameLength, buffer.length);
			return {
				host: origString,
				buffer: Buffer.concat([preSlice, Buffer.from(newString), postSlice])
			};
			break;
		}
		offset += extLength;
	}
	return null;
};

var removeSuffix = function(buffer) {
	var offset = 44;
	offset += buffer[offset]; // session ID length
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

const suffixed = appendSuffix(testBuffer);

if (suffixed == null) {
	throw new Error("no SNI");
} else {
	console.log(suffixed);
}

const normal = removeSuffix(suffixed.buffer);

if (normal == null) {
	throw new Error("no SNI");
} else {
	console.log(normal);
}

console.log(testBuffer.length);
console.log(suffixed.buffer.length);
console.log(normal.buffer.length);*/