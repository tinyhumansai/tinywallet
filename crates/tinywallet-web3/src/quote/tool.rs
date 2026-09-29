//! Agent-tool plumbing shared by every confirm-then-execute flow.

use serde_json::{Value, json};

/// The JSON Schema every execute tool takes: a quote id and an explicit
/// `confirmed` flag, the boundary between quoting and acting.
#[must_use]
pub fn execute_tool_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "quoteId": {"type": "string", "description": "quoteId from a prior web3 quote/call."},
            "confirmed": {"type": "boolean", "description": "Must be true to execute."}
        },
        "required": ["quoteId", "confirmed"],
        "additionalProperties": false
    })
}

/// Turn an operation result into a tool result: pretty-printed JSON on
/// success, the error text otherwise.
#[cfg(feature = "tools")]
#[must_use]
pub fn to_tool_result<T: serde::Serialize>(result: Result<T, String>) -> tinytools::ToolResult {
    match result {
        Ok(value) => match serde_json::to_string_pretty(&value) {
            Ok(text) => tinytools::ToolResult::success(text),
            Err(e) => tinytools::ToolResult::error(format!("failed to serialize web3 result: {e}")),
        },
        Err(e) => tinytools::ToolResult::error(e),
    }
}
