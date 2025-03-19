// Copyright (C) 2025 The MITRE Corporation All Rights Reserved

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    io,
};

use bitvec::prelude::*;
use clap::Parser;
use cli_table::{print_stdout, Cell, CellStruct, Color, Style, Table};
use csv::Writer;
use pclib::core;
use pclib::{
    enforcementresults::{ConstraintResult, EnforcementResults},
    patternmeta,
};
use rayon::prelude::*;
use walkdir::WalkDir;

fn get_table(
    table_data: &mut Vec<Vec<CellStruct>>,
    data_file_path: &str,
    enforced: bool,
    result: &BTreeMap<String, usize>,
    constraint_results: &EnforcementResults,
    all_tags: &BTreeSet<&String>,
    all_constraint_names: &[String],
) {
    // Set our color and logo for if we passed enforcement or not
    let (color, logo, logo_color) = if enforced {
        (None, "✔", Some(Color::Green))
    } else {
        (Some(Color::Red), "❌", Some(Color::Red))
    };

    // Set up first two columns: result and filename
    let mut row = vec![
        logo.cell().foreground_color(logo_color),
        data_file_path.cell().foreground_color(color),
    ];

    // Next add pattern results. Note that we use a BTreeMap for results
    // (and constraint_results) so these results will always come out in
    // key-alphebetic order. We need this constancy for our column
    // headers to make sense.
    for ptn_result in result.values() {
        row.push(ptn_result.cell());
    }

    let cr = constraint_results.get_all_constraint_results();
    // Add constraint results
    for constraint_name in all_constraint_names {
        if let Some(ConstraintResult::Bool { result }) = cr.get(constraint_name) {
            row.push(result.cell());
        } else {
            row.push(false.cell());
        }
    }

    // Output columns for tags
    let returned_tags = constraint_results.get_tags();
    for tag in all_tags {
        row.push(returned_tags.contains(*tag).cell());
    }

    table_data.push(row);
}

fn get_csv<W: io::Write>(
    csv_writer: &mut Writer<W>,
    data_file_path: &str,
    enforced: bool,
    result: &BTreeMap<String, usize>,
    constraint_results: &EnforcementResults,
    all_tags: &BTreeSet<&String>,
    all_constraint_names: &[String],
) {
    // Set our color and logo for if we passed enforcement or not
    let logo = if enforced { "Passed" } else { "Failed" };

    csv_writer.write_field(logo).unwrap();
    csv_writer.write_field(data_file_path).unwrap();

    // Next add pattern results. Note that we use a BTreeMap for results
    // (and constraint_results) so these results will always come out in
    // key-alphebetic order. We need this constancy for our column
    // headers to make sense.
    for ptn_result in result.values() {
        csv_writer.write_field(format!("{}", *ptn_result)).unwrap();
    }

    let cr = constraint_results.get_all_constraint_results();
    // Add constraint results
    for constraint_name in all_constraint_names {
        if let Some(ConstraintResult::Bool { result }) = cr.get(constraint_name) {
            csv_writer
                .write_field(format!("{}", i32::from(*result)))
                .unwrap();
        } else {
            csv_writer.write_field("0").unwrap();
        }
    }

    // Output columns for tags
    let returned_tags = constraint_results.get_tags();
    for tag in all_tags {
        let tag_found = returned_tags.contains(*tag);
        csv_writer
            .write_field(format!("{}", i32::from(tag_found)))
            .unwrap();
    }

    csv_writer.write_record(None::<&[u8]>).unwrap();
}

fn main() {
    /// Quickly searches for binary patterns
    #[derive(Parser, Debug)]
    #[command(
        author,
        version,
        about,
        before_help = "Copyright (C) 2023 The MITRE Corporation All Rights Reserved"
    )]
    struct Args {
        /// Short circut initial .* by seeking for first byte or lookup that matches
        #[arg(short, long = "short-circut")]
        short_circut: bool,

        /// Only shows filename and offeset of match
        #[arg(short, long, action = clap::ArgAction::Count)]
        quiet: u8,

        /// Show a table with an overview of all results
        #[arg(short, long, action = clap::ArgAction::Count)]
        table: u8,

        /// Save CSV results to specified file
        #[arg(short, long, value_name = "FILE")]
        csv: Option<String>,

        /// Map the target file into memory rather than reading it into memory
        #[arg(long)]
        memorymap: bool,

        /// Treat PATTERN_FILE as a meta pattern
        #[arg(short, long)]
        meta: bool,

        /// Pattern file to search for
        #[arg(value_name = "PATTERN_FILE")]
        pattern: String,

        /// Binary file(s) to search in
        #[arg(value_name = "FILE")]
        binary: Vec<String>,
    }
    let matches = Args::parse();

    let mut data_files = vec![];

    // Expand our given data file paths into a list of only files. Essentially,
    // recursively expand directories.
    for data_file in &matches.binary {
        if std::fs::metadata(data_file).unwrap().is_dir() {
            for entry in WalkDir::new(data_file)
                .follow_links(true)
                .into_iter()
                .filter_map(|e| e.ok())
                // Don't return directories
                .filter(|e| e.depth() > 0 && e.metadata().unwrap().is_file())
            {
                data_files.push(entry.path().to_string_lossy().to_string());
            }
        } else {
            // We were given a file, simply add it
            data_files.push(data_file.to_string());
        }
    }

    if matches.meta {
        let meta = patternmeta::PatternMeta::<Msb0>::load_pattern_meta(&matches.pattern);

        // In parallel: run all the patterns and check enforcement of the
        // constraints on all binaries
        let all_results: Vec<_> = data_files
            .par_iter()
            .map(|data_file_path| {
                meta.run_enforce_and_reduce(matches.short_circut, data_file_path, matches.memorymap)
            })
            .collect();

        // Gather up results for pretty formatting
        let total_files = all_results.len();
        let mut total_enforced = 0;
        let mut table_data = vec![];
        let mut titles = vec!["✓".to_string(), "Filename".to_string()];
        let mut tag_totals: HashMap<String, usize> = HashMap::new();

        // Add pattern names to our titles, ensuring they are in alphebetic order
        let mut pattern_names_sorted = meta.pattern_names.clone();
        pattern_names_sorted.sort();
        // Append all our pattern names to our title row
        for pattern_name in pattern_names_sorted {
            titles.push(pattern_name);
        }

        let mut all_tags = BTreeSet::new();
        let mut all_constraint_names = vec![];
        for c in &meta.constraints {
            if let Some(z) = &c.true_tags {
                for t in z {
                    all_tags.insert(t);
                }
            }
            if let Some(z) = &c.false_tags {
                for t in z {
                    all_tags.insert(t);
                }
            }
            all_constraint_names.push(c.name.to_string());
            titles.push(c.name.to_string());
        }

        // Copy all our tags into our title row as well.
        for tag in &all_tags {
            titles.push(tag.to_string());
        }

        let mut csv_writer = None;
        if matches.csv.is_some() {
            let mut csv_writer_inner = Writer::from_path(matches.csv.unwrap()).unwrap();
            csv_writer_inner.write_record(&titles).unwrap();
            csv_writer = Some(csv_writer_inner);
        }

        for (data_file_path, enforced, result, constraint_results) in all_results {
            // Sum tags
            for tag in constraint_results.get_tags() {
                tag_totals.insert(tag.to_owned(), tag_totals.get(tag).unwrap_or(&0) + 1);
            }

            if enforced {
                total_enforced += 1;
                if matches.quiet > 1 {
                    continue;
                }
            }
            if matches.table > 0 {
                get_table(
                    &mut table_data,
                    data_file_path,
                    enforced,
                    &result,
                    &constraint_results,
                    &all_tags,
                    &all_constraint_names,
                );
            }
            if let Some(ref mut c) = csv_writer {
                get_csv(
                    c,
                    data_file_path,
                    enforced,
                    &result,
                    &constraint_results,
                    &all_tags,
                    &all_constraint_names,
                );
            }
        }

        if matches.table > 0 {
            assert!(print_stdout(table_data.table().title(titles)).is_ok());
        }

        if let Some(ref mut c) = csv_writer {
            c.flush().unwrap();
        }

        for (tag, total) in tag_totals {
            println!("{}: {}", tag, total);
        }

        println!(
            "{} out of {} passed enforcement",
            total_enforced, total_files
        );
    } else {
        // The "meta" flag was not used, so just do a single pattern
        let program = core::load_pattern::<Msb0>(None, &matches.pattern, matches.quiet.into());

        // Loop over all input files
        let all_summary_data: Vec<_> = data_files
            .par_iter()
            .map(|data_file_path| {
                let results = core::run_pattern(
                    matches.short_circut,
                    data_file_path,
                    &program,
                    matches.quiet.into(),
                    matches.memorymap,
                );

                let matches: Vec<usize> = results
                    .iter()
                    .filter_map(|x| {
                        if x.matched {
                            Some(x.saved.as_ref().unwrap().start.unwrap())
                        } else {
                            None
                        }
                    })
                    .collect();

                (data_file_path, matches.len(), matches)
            })
            .collect();

        let table_data = all_summary_data
            .iter()
            .map(|(data_file_path, num_matches, matches)| {
                // Save off some result information for pretty printing in the table
                let color = match num_matches {
                    0 => Some(Color::Red),
                    1 => None,
                    _ => Some(Color::Yellow),
                };
                let some_matches: Vec<String> = matches
                    .iter()
                    .enumerate()
                    .map(|(idx, val)| match idx {
                        0..=5 => format!("0x{:X}", val),
                        6 => "...".to_string(),
                        _ => "".to_string(),
                    })
                    .collect();
                vec![
                    (*data_file_path).cell().foreground_color(color),
                    num_matches.cell().foreground_color(color),
                    some_matches.join(",").cell().foreground_color(color),
                ]
            });

        // Print a summary table if we were asked to
        if matches.table > 0 {
            assert!(print_stdout(table_data.table().title(vec![
                "Binary",
                "# Matches",
                "Match Values"
            ]))
            .is_ok());

            let mut summary = [0usize; 3];

            all_summary_data
                .iter()
                .fold(&mut summary, |a, (_, num_matches, _)| {
                    match num_matches {
                        0 => a[0] += 1,
                        1 => a[1] += 1,
                        _ => a[2] += 1,
                    }
                    a
                });

            println!(
                "Pattern found 0  times in {:>5} files
Pattern found 1  time  in {:>5} files
Pattern found 2+ times in {:>5} files",
                summary[0], summary[1], summary[2]
            );
        } else {
            for (file, num, matches) in all_summary_data {
                if num > 0 {
                    println!("File: {}\nmatches at offset(s):", file);
                    for m in matches {
                        println!("0x{:X}", m);
                    }
                }
            }
        }
    }
}
