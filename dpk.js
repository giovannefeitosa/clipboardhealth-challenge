const crypto = require("crypto");

const TRIVIAL_PARTITION_KEY = "0";
const MAX_PARTITION_KEY_LENGTH = 256;

/**
 * Private function so we don't need to repeat this code inside `deterministicPartitionKey` function.
 */
function generateCandidate(data) {
  return crypto.createHash("sha3-512").update(data).digest("hex");
}

/**
 * Receives an event and returns a deterministic partition key.
 *
 * @param {{ partitionKey?: string; }} event
 * @returns
 */
exports.deterministicPartitionKey = (event) => {
  // if we don't have enough to proceed
  if (!event) return TRIVIAL_PARTITION_KEY;
  if (!event?.partitionKey) return generateCandidate(JSON.stringify(event));

  // get partition as String
  const eventString =
    typeof event.partitionKey === "string"
      ? event.partitionKey
      : JSON.stringify(event.partitionKey);

  // if it's too long, we need to hash it
  return eventString.length <= MAX_PARTITION_KEY_LENGTH
    ? eventString
    : generateCandidate(JSON.stringify(event));
};
