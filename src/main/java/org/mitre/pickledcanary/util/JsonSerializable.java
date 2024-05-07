package org.mitre.pickledcanary.util;

import org.json.JSONObject;

/**
 * Indicates that an object can be serialized into a JSONObject.
 */
public interface JsonSerializable {
    JSONObject getJson();
}
