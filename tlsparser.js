const testBuffer = Buffer.from("16030100b5010000b10303626b85b9ac4e240bf166dfcb89943680f05adf0f9c7872ca72c42ad7106c108700001ec02bc02fcca9cca8c02cc030c00ac009c013c01400330039002f0035000a0100006a0000000e000c0000096c6f63616c686f737400170000ff01000100000a000a0008001d001700180019000b00020100002300000010000e000c02683208687474702f312e31000500050100000000000d0018001604030503060308040805080604010501060102030201", "hex");

/*var parsed = {
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

parsed.handshake.clientHello.cipherSuitesLength = buffer.readUIntBE();*/

var appendSuffix = function(buffer) {
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
console.log(normal.buffer.length);