
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.querylanguage.tokenizer.api;

public interface ContinuedMatcher {
	boolean op(StringStream stream, int length);
}
