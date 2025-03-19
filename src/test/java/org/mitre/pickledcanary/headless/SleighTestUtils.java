// Copyright (C) 2025 The MITRE Corporation All Rights Reserved
package org.mitre.pickledcanary.headless;

import java.net.URL;

import generic.jar.ResourceFile;
import generic.test.AbstractGenericTest;
import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;

public class SleighTestUtils {
	/* Retrieves a Sleigh resource from a filename */
	public static ResourceFile getSleighResource(String name) {
		URL url = SleighTestUtils.class.getClassLoader().getResource("sleigh/" + name);

		if (url == null) {
			return null;
		}

		return new ResourceFile(url.getPath());
	}

	/* Quickly create a SleighLanguage instance from .ldefs */
	public static SleighLanguage lazyLanguage(ResourceFile lDefsFile) {

		/* This constructor is private so we need to invoke it using the
		 * invokeConstructor method */
		SleighLanguageProvider provider = (SleighLanguageProvider) AbstractGenericTest.invokeConstructor(
				SleighLanguageProvider.class, new Class<?>[] {ResourceFile.class}, new Object[] {lDefsFile});

		/* Get the SleighLanguage we just added to SleighLanguageProvider
		 * using LanguageID from its LanguageDescription */
	    return (SleighLanguage) provider.getLanguage(provider.getLanguageDescriptions()[0].getLanguageID());
	}
}
