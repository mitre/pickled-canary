
// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

package org.mitre.pickledcanary.patterngenerator.output.steps;

import java.util.List;

import org.mitre.pickledcanary.util.JsonSerializable;


public interface Data extends JsonSerializable {
	List<Integer> mask();
}