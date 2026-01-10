package helper

import (
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// YAMLUpdate represents a single YAML update operation
type YAMLUpdate struct {
	Path      string
	Value     interface{} // For scalar values (int, bool, string, float64, nil)
	ListValue []string    // For list values (takes precedence if not nil)
}

// UpdateYAMLPaths updates multiple values at dot-separated paths in YAML content
// Supports array indexing: "users.0.name", "items.2.value"
// Example: UpdateYAMLPaths(content, []YAMLUpdate{
//
//	{Path: "middlewares.rate-limit.rateLimit.average", Value: 100},
//	{Path: "middlewares.rate-limit.rateLimit.burst", Value: 200},
//	{Path: "users.0.name", Value: "admin"},
//
// })
func UpdateYAMLPaths(content string, updates []YAMLUpdate) (string, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		return content, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return content, fmt.Errorf("invalid YAML document")
	}

	var errors []string
	for _, u := range updates {
		if u.Path == "" {
			errors = append(errors, "empty path")
			continue
		}
		parts := strings.Split(u.Path, ".")
		// Validate no empty segments
		hasEmptySegment := false
		for _, p := range parts {
			if p == "" {
				errors = append(errors, fmt.Sprintf("%s: path contains empty segment", u.Path))
				hasEmptySegment = true
				break
			}
		}
		if hasEmptySegment {
			continue
		}
		var err error
		if u.ListValue != nil {
			err = setNodeList(root.Content[0], parts, u.ListValue)
		} else {
			err = setNodeValue(root.Content[0], parts, u.Value)
		}
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", u.Path, err))
		}
	}

	out, err := yaml.Marshal(&root)
	if err != nil {
		return content, fmt.Errorf("failed to marshal YAML: %w", err)
	}

	if len(errors) > 0 {
		return string(out), fmt.Errorf("some updates failed: %s", strings.Join(errors, "; "))
	}

	return string(out), nil
}

// UpdateYAMLPath updates a single value (convenience wrapper)
func UpdateYAMLPath(content string, path string, value interface{}) (string, error) {
	return UpdateYAMLPaths(content, []YAMLUpdate{{Path: path, Value: value}})
}

// UpdateYAMLList updates a single list (convenience wrapper)
func UpdateYAMLList(content string, path string, values []string) (string, error) {
	return UpdateYAMLPaths(content, []YAMLUpdate{{Path: path, ListValue: values}})
}

// GetYAMLPath gets a value at a dot-separated path in YAML content
// Supports array indexing: "users.0.name"
func GetYAMLPath(content string, path string) (interface{}, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		return nil, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil, fmt.Errorf("invalid YAML document")
	}

	parts, err := validatePath(path)
	if err != nil {
		return nil, err
	}

	node, err := getNode(root.Content[0], parts)
	if err != nil {
		return nil, err
	}

	return nodeToValue(node), nil
}

// InsertYAMLArrayItem inserts a value into an array at the specified path
// The value is inserted at the end of the array, or at a specific index if provided
// Path should point to the array, not including the index
// Example: InsertYAMLArrayItem(content, "routers.api.middlewares", "sentinel_vpn@file")
func InsertYAMLArrayItem(content string, path string, value string) (string, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		return content, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return content, fmt.Errorf("invalid YAML document")
	}

	parts, err := validatePath(path)
	if err != nil {
		return content, err
	}

	node, err := getNode(root.Content[0], parts)
	if err != nil {
		return content, err
	}

	if node.Kind != yaml.SequenceNode {
		return content, fmt.Errorf("path does not point to an array")
	}

	// Check if value already exists
	for _, item := range node.Content {
		if item != nil && item.Value == value {
			return content, nil // Already exists, no change needed
		}
	}

	// Append new item
	newNode := &yaml.Node{
		Kind:  yaml.ScalarNode,
		Tag:   "!!str",
		Value: value,
	}
	node.Content = append(node.Content, newNode)

	out, err := yaml.Marshal(&root)
	if err != nil {
		return content, fmt.Errorf("failed to marshal YAML: %w", err)
	}

	return string(out), nil
}

// RemoveYAMLArrayItem removes a value from an array at the specified path
// Path should point to the array, not including the index
// Example: RemoveYAMLArrayItem(content, "routers.api.middlewares", "sentinel_vpn@file")
func RemoveYAMLArrayItem(content string, path string, value string) (string, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		return content, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return content, fmt.Errorf("invalid YAML document")
	}

	parts, err := validatePath(path)
	if err != nil {
		return content, err
	}

	node, err := getNode(root.Content[0], parts)
	if err != nil {
		return content, err
	}

	if node.Kind != yaml.SequenceNode {
		return content, fmt.Errorf("path does not point to an array")
	}

	// Find and remove the item
	newContent := make([]*yaml.Node, 0, len(node.Content))
	found := false
	for _, item := range node.Content {
		if item != nil && item.Value == value {
			found = true
			continue // Skip this item (remove it)
		}
		newContent = append(newContent, item)
	}

	if !found {
		return content, nil // Item not found, no change needed
	}

	node.Content = newContent

	out, err := yaml.Marshal(&root)
	if err != nil {
		return content, fmt.Errorf("failed to marshal YAML: %w", err)
	}

	return string(out), nil
}

// ArrayContainsYAMLItem checks if an array at the specified path contains the value
func ArrayContainsYAMLItem(content string, path string, value string) (bool, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		return false, fmt.Errorf("failed to parse YAML: %w", err)
	}

	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return false, fmt.Errorf("invalid YAML document")
	}

	parts, err := validatePath(path)
	if err != nil {
		return false, err
	}

	node, err := getNode(root.Content[0], parts)
	if err != nil {
		return false, err
	}

	if node.Kind != yaml.SequenceNode {
		return false, fmt.Errorf("path does not point to an array")
	}

	for _, item := range node.Content {
		if item != nil && item.Value == value {
			return true, nil
		}
	}

	return false, nil
}

// setNodeValue navigates to the path and sets the value
// Supports both mapping keys and array indices (e.g., "users.0.name")
// Supports types: int, int64, float64, bool, string, nil
func setNodeValue(node *yaml.Node, path []string, value interface{}) error {
	if len(path) == 0 {
		return fmt.Errorf("empty path")
	}

	// Handle array indexing
	if node.Kind == yaml.SequenceNode {
		idx, err := strconv.Atoi(path[0])
		if err != nil {
			return fmt.Errorf("expected numeric index for sequence, got: %s", path[0])
		}
		if idx < 0 || idx >= len(node.Content) {
			return fmt.Errorf("index out of bounds: %d (array has %d elements)", idx, len(node.Content))
		}
		if len(path) == 1 {
			return setScalarValue(node.Content[idx], value)
		}
		return setNodeValue(node.Content[idx], path[1:], value)
	}

	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("expected mapping node at path, got %v", nodeKindString(node.Kind))
	}

	if err := validateMappingNode(node); err != nil {
		return err
	}

	// Find the key in the mapping
	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valueNode := node.Content[i+1]
		if keyNode == nil || valueNode == nil {
			continue
		}

		if keyNode.Value == path[0] {
			if len(path) == 1 {
				return setScalarValue(valueNode, value)
			}
			// Navigate deeper
			return setNodeValue(valueNode, path[1:], value)
		}
	}

	return fmt.Errorf("key not found: %s", path[0])
}

// setScalarValue sets a scalar value on a node
// Supports: int, int64, float64, bool, string, nil
func setScalarValue(node *yaml.Node, value interface{}) error {
	if node == nil {
		return fmt.Errorf("cannot set value on nil node")
	}
	node.Kind = yaml.ScalarNode

	switch v := value.(type) {
	case nil:
		node.Tag = "!!null"
		node.Value = "null"
	case int:
		node.Tag = "!!int"
		node.Value = strconv.Itoa(v)
	case int64:
		node.Tag = "!!int"
		node.Value = strconv.FormatInt(v, 10)
	case float64:
		node.Tag = "!!float"
		node.Value = strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		node.Tag = "!!bool"
		node.Value = strconv.FormatBool(v)
	case string:
		node.Tag = "!!str"
		node.Value = v
	default:
		return fmt.Errorf("unsupported value type: %T", value)
	}
	return nil
}

// setNodeList navigates to the path and sets a list value
// Supports array indexing in path (e.g., "users.0.items")
func setNodeList(node *yaml.Node, path []string, values []string) error {
	if len(path) == 0 {
		return fmt.Errorf("empty path")
	}

	// Handle array indexing
	if node.Kind == yaml.SequenceNode {
		idx, err := strconv.Atoi(path[0])
		if err != nil {
			return fmt.Errorf("expected numeric index for sequence, got: %s", path[0])
		}
		if idx < 0 || idx >= len(node.Content) {
			return fmt.Errorf("index out of bounds: %d (array has %d elements)", idx, len(node.Content))
		}
		if len(path) == 1 {
			// Set the list directly on this array element
			elemNode := node.Content[idx]
			elemNode.Kind = yaml.SequenceNode
			elemNode.Tag = "!!seq"
			elemNode.Content = make([]*yaml.Node, len(values))
			for j, v := range values {
				elemNode.Content[j] = &yaml.Node{
					Kind:  yaml.ScalarNode,
					Tag:   "!!str",
					Value: v,
					Style: yaml.DoubleQuotedStyle,
				}
			}
			return nil
		}
		return setNodeList(node.Content[idx], path[1:], values)
	}

	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("expected mapping node at path, got %v", nodeKindString(node.Kind))
	}

	if err := validateMappingNode(node); err != nil {
		return err
	}

	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valueNode := node.Content[i+1]
		if keyNode == nil || valueNode == nil {
			continue
		}

		if keyNode.Value == path[0] {
			if len(path) == 1 {
				// Set the list
				valueNode.Kind = yaml.SequenceNode
				valueNode.Tag = "!!seq"
				valueNode.Content = make([]*yaml.Node, len(values))
				for j, v := range values {
					valueNode.Content[j] = &yaml.Node{
						Kind:  yaml.ScalarNode,
						Tag:   "!!str",
						Value: v,
						Style: yaml.DoubleQuotedStyle,
					}
				}
				return nil
			}
			return setNodeList(valueNode, path[1:], values)
		}
	}

	return fmt.Errorf("key not found: %s", path[0])
}

// getNode navigates to the path and returns the node
// Supports both mapping keys and array indices (e.g., "users.0.name")
func getNode(node *yaml.Node, path []string) (*yaml.Node, error) {
	if len(path) == 0 {
		return node, nil
	}

	// Handle array indexing
	if node.Kind == yaml.SequenceNode {
		idx, err := strconv.Atoi(path[0])
		if err != nil {
			return nil, fmt.Errorf("expected numeric index for sequence, got: %s", path[0])
		}
		if idx < 0 || idx >= len(node.Content) {
			return nil, fmt.Errorf("index out of bounds: %d (array has %d elements)", idx, len(node.Content))
		}
		if len(path) == 1 {
			return node.Content[idx], nil
		}
		return getNode(node.Content[idx], path[1:])
	}

	if node.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("expected mapping node at path, got %v", nodeKindString(node.Kind))
	}

	if err := validateMappingNode(node); err != nil {
		return nil, err
	}

	for i := 0; i < len(node.Content); i += 2 {
		keyNode := node.Content[i]
		valueNode := node.Content[i+1]
		if keyNode == nil || valueNode == nil {
			continue
		}

		if keyNode.Value == path[0] {
			if len(path) == 1 {
				return valueNode, nil
			}
			return getNode(valueNode, path[1:])
		}
	}

	return nil, fmt.Errorf("key not found: %s", path[0])
}

// nodeToValue converts a yaml.Node to a Go value
// Respects YAML tags to avoid aggressive type coercion
func nodeToValue(node *yaml.Node) interface{} {
	if node == nil {
		return nil
	}
	switch node.Kind {
	case yaml.ScalarNode:
		// Check for null
		if node.Tag == "!!null" || node.Value == "null" || node.Value == "~" || node.Value == "" {
			return nil
		}

		// Respect explicit tags - don't coerce if tag says string
		if node.Tag == "!!str" {
			return node.Value
		}

		// For explicitly tagged values, respect the tag
		if node.Tag == "!!int" {
			if i, err := strconv.ParseInt(node.Value, 10, 64); err == nil {
				// Return int if it fits, otherwise int64
				if i >= int64(int(^uint(0)>>1)*-1-1) && i <= int64(int(^uint(0)>>1)) {
					return int(i)
				}
				return i
			}
		}

		if node.Tag == "!!float" {
			if f, err := strconv.ParseFloat(node.Value, 64); err == nil {
				return f
			}
		}

		if node.Tag == "!!bool" {
			if b, err := strconv.ParseBool(node.Value); err == nil {
				return b
			}
		}

		// For untagged values, try to infer type but be conservative
		// Only parse as int if it looks exactly like an int
		if node.Tag == "" || node.Tag == "!!str" {
			return node.Value
		}

		// Try int
		if i, err := strconv.Atoi(node.Value); err == nil {
			return i
		}

		// Try float
		if f, err := strconv.ParseFloat(node.Value, 64); err == nil {
			return f
		}

		// Try bool (only for explicit true/false)
		if node.Value == "true" {
			return true
		}
		if node.Value == "false" {
			return false
		}

		return node.Value

	case yaml.SequenceNode:
		// Return mixed-type slice for sequences
		var list []interface{}
		for _, n := range node.Content {
			list = append(list, nodeToValue(n))
		}
		return list

	case yaml.MappingNode:
		// Return map for mapping nodes
		// Guard against malformed mapping with odd content length
		if len(node.Content)%2 != 0 {
			return nil
		}
		result := make(map[string]interface{})
		for i := 0; i < len(node.Content); i += 2 {
			keyNode := node.Content[i]
			valueNode := node.Content[i+1]
			if keyNode == nil || valueNode == nil {
				continue
			}
			result[keyNode.Value] = nodeToValue(valueNode)
		}
		return result

	default:
		return nil
	}
}

// validatePath splits and validates a dot-separated path
func validatePath(path string) ([]string, error) {
	if path == "" {
		return nil, fmt.Errorf("empty path")
	}
	parts := strings.Split(path, ".")
	for _, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("path contains empty segment")
		}
	}
	return parts, nil
}

// validateMappingNode checks if a mapping node has valid even-length content
func validateMappingNode(node *yaml.Node) error {
	if node.Kind == yaml.MappingNode && len(node.Content)%2 != 0 {
		return fmt.Errorf("malformed mapping node: odd number of elements")
	}
	return nil
}

// nodeKindString returns a human-readable string for yaml.Kind
func nodeKindString(kind yaml.Kind) string {
	switch kind {
	case yaml.DocumentNode:
		return "document"
	case yaml.SequenceNode:
		return "sequence"
	case yaml.MappingNode:
		return "mapping"
	case yaml.ScalarNode:
		return "scalar"
	case yaml.AliasNode:
		return "alias"
	default:
		return fmt.Sprintf("unknown(%d)", kind)
	}
}
