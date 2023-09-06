// Copyright (C) 2023 The MITRE Corporation All Rights Reserved

use hashbrown::HashMap;

use bitvec::prelude::*;
use clap::Parser;
use pclib::core;
use pclib::patternmeta;
use petgraph::dot::Dot;
use petgraph::graph::Graph;
use petgraph::graph::NodeIndex;
use std::fs::File;
use std::io::prelude::*;
use treesearchlib::bitstructs::Op;
use treesearchlib::bitstructs::Pattern;

fn populate_graph_recursive<'a>(
    step: usize,
    graph: &mut Graph<&'a str, u32>,
    node_id_map: &mut HashMap<usize, NodeIndex>,
    debug_strs: &'a HashMap<usize, String>,
    program: &Pattern<Msb0>,
) {
    if node_id_map.get(&step).is_some() {
        return;
    }

    let node = graph.add_node(debug_strs.get(&step).unwrap());
    node_id_map.insert(step, node);

    let next_steps = match &program.steps[step] {
        Op::Byte { value: _ }
        | Op::MaskedByte { mask: _, value: _ }
        | Op::ByteMultiNonconsuming { value: _ }
        | Op::Match { match_number: _ }
        | Op::Lookup { data: _ }
        | Op::LookupQuick { bytes: _, data: _ }
        | Op::AnyByte
        | Op::AnyByteSequence {
            min: _,
            max: _,
            interval: _,
        }
        | Op::NegativeLookahead { pattern: _ } => vec![],
        Op::Jmp { dest } => vec![*dest],
        Op::Split { dest1, dest2 } => vec![*dest1, *dest2],
        Op::SplitMulti { dests } => dests.to_vec(),
        Op::SaveStart | Op::Save { slot: _ } | Op::Label { value: _ } => vec![step + 1],
    };
    for next_step in next_steps {
        populate_graph_recursive(next_step, graph, node_id_map, debug_strs, program);
        graph.add_edge(
            *node_id_map.get(&step).unwrap(),
            *node_id_map.get(&next_step).unwrap(),
            100,
        );
    }
}

fn main() {
    /// Quickly search for a binary patterns
    #[derive(Parser, Debug)]
    #[command(author, version, about)]
    struct Args {
        /// Treat PATTERN_FILE as a meta pattern
        #[arg(short, long)]
        meta: bool,

        /// Pattern file to search for
        #[arg(value_name = "PATTERN_FILE")]
        pattern: String,

        /// Where to write results
        #[arg(value_name = "OUTPUT")]
        output: String,
    }
    let matches = Args::parse();

    let program = if matches.meta {
        let meta = patternmeta::PatternMeta::<Msb0>::load_pattern_meta(&matches.pattern);
        meta.combined_pattern.unwrap()
    } else {
        // The "meta" flag was not used, so just do a single pattern
        core::load_pattern::<Msb0>(None, &matches.pattern, 3)
    };

    let mut weights = HashMap::new();
    program.get_weights(0, &mut vec![], &mut weights);

    let mut graph = Graph::<&str, u32>::new();
    let mut node_id_map = HashMap::new();
    let debug_strs: HashMap<usize, String> = program
        .steps
        .iter()
        .enumerate()
        .map(|(i, x)| {
            (
                i,
                format!("{}:\nweight: {:#?}\n{:#x?}", i, weights.get(&i).unwrap(), x),
            )
        })
        .collect();
    for (idx, _) in program.steps.iter().enumerate() {
        let node = graph.add_node(debug_strs.get(&idx).unwrap());
        node_id_map.insert(idx, node);
    }

    for (idx, step) in program.steps.iter().enumerate() {
        match step {
            Op::Jmp { dest } => {
                graph.add_edge(
                    *node_id_map.get(&idx).unwrap(),
                    *node_id_map.get(dest).unwrap(),
                    100,
                );
            }
            Op::Split { dest1, dest2 } => {
                graph.add_edge(
                    *node_id_map.get(&idx).unwrap(),
                    *node_id_map.get(dest1).unwrap(),
                    51,
                );

                graph.add_edge(
                    *node_id_map.get(&idx).unwrap(),
                    *node_id_map.get(dest2).unwrap(),
                    49,
                );
            }
            Op::SplitMulti { dests } => {
                for dest in dests {
                    graph.add_edge(
                        *node_id_map.get(&idx).unwrap(),
                        *node_id_map.get(dest).unwrap(),
                        50,
                    );
                }
            }
            Op::Match { match_number: _ } => {}
            Op::Save { slot: _ }
            | Op::Byte { value: _ }
            | Op::MaskedByte { mask: _, value: _ }
            | Op::ByteMultiNonconsuming { value: _ }
            | Op::SaveStart
            | Op::Label { value: _ }
            | Op::AnyByte
            | Op::AnyByteSequence {
                min: _,
                max: _,
                interval: _,
            }
            | Op::Lookup { data: _ }
            | Op::LookupQuick { bytes: _, data: _ }
            | Op::NegativeLookahead { pattern: _ } => {
                if idx + 1 < program.steps.len() {
                    graph.add_edge(
                        *node_id_map.get(&idx).unwrap(),
                        *node_id_map.get(&(idx + 1)).unwrap(),
                        70,
                    );
                }
            }
        }
    }

    let mut file = File::create(&matches.output).unwrap();
    file.write_all(format!("{}", Dot::new(&graph)).as_bytes())
        .unwrap();

    // Now do just the trivially reachable graph
    let mut graph = Graph::<&str, u32>::new();
    let mut node_id_map = HashMap::new();
    populate_graph_recursive(0, &mut graph, &mut node_id_map, &debug_strs, &program);

    let mut file = File::create(format!("{}_reachable", &matches.output)).unwrap();
    file.write_all(format!("{}", Dot::new(&graph)).as_bytes())
        .unwrap();
}
