const crypto = require("crypto");

/**
 * Receives an event and returns a deterministic partition key.
 *
 * @param {{ partitionKey?: string; }} event
 * @returns
 */
exports.deterministicPartitionKey = (event) => {
  const TRIVIAL_PARTITION_KEY = "0";
  const MAX_PARTITION_KEY_LENGTH = 256;
  let candidate;

  // if event exists
  if (event) {
    if (event.partitionKey) {
      // if event has a partition key, we use it
      candidate = event.partitionKey;
    } else {
      // if event has no partition key, we convert the event to a hash string
      // and use it as a partition key
      const data = JSON.stringify(event);
      // https://nodejs.org/api/crypto.html#hashdigestencoding
      candidate = crypto.createHash("sha3-512").update(data).digest("hex");
    }
  }

  if (candidate) {
    // if candidate is not a string, it should be
    if (typeof candidate !== "string") {
      // JSON.stringify(1) === "1"
      candidate = JSON.stringify(candidate);
    }
  } else {
    // THIS SHOULD NEVER HAPPEN
    candidate = TRIVIAL_PARTITION_KEY;
  }
  // if candidate is too long
  // we apply a hash so it fits in the partition key
  if (candidate.length > MAX_PARTITION_KEY_LENGTH) {
    candidate = crypto.createHash("sha3-512").update(candidate).digest("hex");
  }
  return candidate;
};
