package neo4j

// relationshipPropertiesToMap converts typed RelationshipProperties to map for Neo4j driver
func relationshipPropertiesToMap(props RelationshipProperties) map[string]interface{} {
	result := make(map[string]interface{})

	if !props.CreatedAt.IsZero() {
		result["created_at"] = props.CreatedAt.Unix()
	}
	if props.Weight != 0 {
		result["weight"] = props.Weight
	}
	if props.Confidence != 0 {
		result["confidence"] = props.Confidence
	}
	if props.Controller {
		result["controller"] = props.Controller
	}
	if props.BlockOwnerDeletion {
		result["block_owner_deletion"] = props.BlockOwnerDeletion
	}
	if props.Port != 0 {
		result["port"] = props.Port
	}
	if props.Protocol != "" {
		result["protocol"] = props.Protocol
	}
	if props.Direction != "" {
		result["direction"] = props.Direction
	}
	if props.Latency > 0 {
		result["latency"] = props.Latency.Milliseconds()
	}
	if props.Count > 0 {
		result["count"] = props.Count
	}

	return result
}