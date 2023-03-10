const crypto = require("crypto");
const { deterministicPartitionKey } = require("./dpk");

jest.mock("crypto");

const mockFactory = {
  expectedHashAlgorithm: "sha3-512",
  expectedDigestEcoding: "hex",
  before: () => {
    const mockHash = mockFactory.mockHash();

    crypto.createHash.mockImplementation((algorithm) => {
      if (algorithm === mockFactory.expectedHashAlgorithm) {
        return mockHash;
      }
      throw new Error(`Unexpected algorithm: ${algorithm}`);
    });

    return { mockHash };
  },
  mockHash: () => ({
    update: jest.fn().mockReturnThis(),
    digest: jest.fn().mockReturnValue("hash"),
  }),
};

describe("deterministicPartitionKey", () => {
  let mockHash = null;

  beforeEach(() => {
    const mocks = mockFactory.before();
    mockHash = mocks.mockHash;
  });

  it("Ensure the mocks works", () => {
    // const { mockHash } = mockFactory.before();
    const mockEvent = {};
    deterministicPartitionKey(mockEvent);
    expect(crypto.createHash).toHaveBeenCalledWith(
      mockFactory.expectedHashAlgorithm
    );
    expect(mockHash.update).toHaveBeenCalledWith(JSON.stringify(mockEvent));
    expect(mockHash.digest).toHaveBeenCalledWith(
      mockFactory.expectedDigestEcoding
    );
  });

  it("Returns the literal '0' when given no input", () => {
    const trivialKey = deterministicPartitionKey();
    expect(trivialKey).toBe("0");
  });

  it("If the event.partitionKey is a String, it returns that", () => {
    const event = {
      partitionKey: "foo",
    };

    const key = deterministicPartitionKey(event);
    expect(key).toBe("foo");
  });

  it("If event.partitionKey is a number, returns this number as string", () => {
    const mockEvent = {
      partitionKey: 1,
    };

    const key = deterministicPartitionKey(mockEvent);
    expect(key).toBe("1");
  });

  it("Receives a hash of the event if it has no partitionKey", () => {
    const mockEvent = {};

    const key = deterministicPartitionKey(mockEvent);
    expect(key).toBe("hash");
  });

  it("If event.partitionKey is an object or array, returns JSON.stringify(event)", () => {
    const mockEvent = {
      partitionKey: {
        hire: "me",
      },
    };

    const key = deterministicPartitionKey(mockEvent);
    expect(key).toBe(JSON.stringify(mockEvent.partitionKey));
  });

  it("If the event.partitionKey is a String, but it's too long, returns a hash", () => {
    const mockEvent = {
      partitionKey: "hire-me".repeat(250),
    };

    const key = deterministicPartitionKey(mockEvent);
    expect(key).toBe("hash");
  });

  it("If the event.partitionKey is an object, but it's too long, returns a hash", () => {
    const mockEvent = {
      partitionKey: {
        hire: "me".repeat(250),
      },
    };

    const key = deterministicPartitionKey(mockEvent);
    expect(key).toBe("hash");
  });
});
