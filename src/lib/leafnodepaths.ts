import { JSONPath } from "jsonpath-plus";

export function getLeafNodesWithPath(verifiableCredential, obj, path = "$.credentialSubject.") {
  // Array to store leaf nodes with paths
  let leafNodesWithPath = [];

  // Recursive function to traverse the object
  function traverse(obj, currentPath) {
    for (let key in obj) {
      const newPath = currentPath !== "$.credentialSubject." ? `${currentPath}.${key}` : `${currentPath}${key}`;


			// Add leaf node with path to the array
			if (Object.keys(obj[key]).length === 1 && !(obj[key] instanceof Array) && obj[key].display) {
				console.log("Path = ", newPath)
				console.log("Value found in VC  ", JSONPath({path: newPath, json: verifiableCredential}).length)
				const valueFoundInVC = JSONPath({path: newPath, json: verifiableCredential}).length != 0 ? JSONPath({path: newPath, json: verifiableCredential})[0] : "*****";
				leafNodesWithPath.push({ key: key, path: newPath, friendlyName: obj[key].display[0].name, value: valueFoundInVC });
			}
			else if (typeof obj[key] === "object" && obj[key] !== null) {
        // Recursively traverse nested objects
        traverse(obj[key], newPath);
      }

    }
  }

  // Start traversing the object
  traverse(obj, path);

	console.log("Leafnode paths = ", leafNodesWithPath)
  // Group leaf nodes by path
	return leafNodesWithPath
}
