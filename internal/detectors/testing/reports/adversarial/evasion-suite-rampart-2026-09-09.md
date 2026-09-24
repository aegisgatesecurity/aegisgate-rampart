# AegisGate Rampart — Adversarial Evasion Suite

**Timestamp**: 2026-09-09T15:06:26-05:00  
**Suite Phase**: rampart-0a  
**Go Version**: 1.26  

## Overall Evasion Resistance

| Metric | Value |
|--------|-------|
| Total Tests | 2600 |
| Total Detected | 305 |
| Raw Detection Rate | 11.7% |
| Weighted Detection Rate | 11.7% |
| **Evasion Resistance Score** | **11.7/100** |
| 95% Wilson CI | [10.5%–13.0%] |

## Baseline (Unmodified Payloads)

| Metric | Value |
|--------|-------|
| Total Payloads | 52 |
| Detected | 6 |
| Detection Rate | 11.5% |
| 95% Wilson CI | [5.4%–23.0%] |

## Per-Category Results

| Category | Variants | Tests | Detected | Detection Rate | 95% CI |
|----------|----------|-------|----------|-----------------|--------|
| character_substitution | 10 | 520 | 65 | 12.5% | [9.9%–15.6%] |
| encoding_evasion | 10 | 520 | 19 | 3.7% | [2.4%–5.6%] |
| linguistic_obfuscation | 10 | 520 | 61 | 11.7% | [9.2%–14.8%] |
| whitespace_manipulation | 10 | 520 | 58 | 11.2% | [8.7%–14.1%] |
| prompt_fragmentation | 10 | 520 | 102 | 19.6% | [16.4%–23.2%] |

## Per-Variant Breakdown

### character_substitution

| Variant | Total | Detected | Rate |
|---------|-------|----------|------|
| char_substitute_symbols | 52 | 6 | 11.5% |
| char_delete_vowels | 52 | 6 | 11.5% |
| char_transpose_adjacent | 52 | 11 | 21.2% |
| l33t_aggressive | 52 | 4 | 7.7% |
| char_insert_dots | 52 | 6 | 11.5% |
| char_repeat | 52 | 4 | 7.7% |
| l33t_common | 52 | 9 | 17.3% |
| char_insert_hyphens | 52 | 6 | 11.5% |
| keyboard_walk_shift | 52 | 2 | 3.8% |
| char_reverse_words | 52 | 11 | 21.2% |

### encoding_evasion

| Variant | Total | Detected | Rate |
|---------|-------|----------|------|
| base64_prefix | 52 | 2 | 3.8% |
| base64_full | 52 | 2 | 3.8% |
| unicode_escapes | 52 | 0 | 0.0% |
| backslash_escape | 52 | 3 | 5.8% |
| mixed_encoding | 52 | 1 | 1.9% |
| rot13_partial | 52 | 2 | 3.8% |
| url_encode_spaces | 52 | 1 | 1.9% |
| url_encode_keywords | 52 | 4 | 7.7% |
| html_entity_encode | 52 | 4 | 7.7% |
| hex_escape_encode | 52 | 0 | 0.0% |

### linguistic_obfuscation

| Variant | Total | Detected | Rate |
|---------|-------|----------|------|
| hypothetical_framing | 52 | 6 | 11.5% |
| polite_wrapper | 52 | 6 | 11.5% |
| sentence_restructure | 52 | 5 | 9.6% |
| indirect_phrasing | 52 | 9 | 17.3% |
| definition_bypass | 52 | 6 | 11.5% |
| academic_tone | 52 | 6 | 11.5% |
| story_framing | 52 | 6 | 11.5% |
| synonym_substitution | 52 | 5 | 9.6% |
| passive_voice | 52 | 6 | 11.5% |
| negation_inversion | 52 | 6 | 11.5% |

### whitespace_manipulation

| Variant | Total | Detected | Rate |
|---------|-------|----------|------|
| zero_width_joiner | 52 | 6 | 11.5% |
| line_break_scatter | 52 | 6 | 11.5% |
| mixed_whitespace | 52 | 6 | 11.5% |
| word_split_newline | 52 | 4 | 7.7% |
| zero_width_nonjoiner | 52 | 6 | 11.5% |
| zero_width_space | 52 | 6 | 11.5% |
| extra_spaces | 52 | 6 | 11.5% |
| tab_insertion | 52 | 6 | 11.5% |
| double_spaces | 52 | 6 | 11.5% |
| unicode_invisible | 52 | 6 | 11.5% |

### prompt_fragmentation

| Variant | Total | Detected | Rate |
|---------|-------|----------|------|
| nested_instruction | 52 | 52 | 100.0% |
| concatenation_hint | 52 | 5 | 9.6% |
| split_triples | 52 | 6 | 11.5% |
| markdown_headers | 52 | 6 | 11.5% |
| encoded_boundary | 52 | 6 | 11.5% |
| system_prefix | 52 | 6 | 11.5% |
| split_half | 52 | 5 | 9.6% |
| progressive_disclosure | 52 | 4 | 7.7% |
| context_boundary | 52 | 6 | 11.5% |
| role_delimiter | 52 | 6 | 11.5% |

## Sample Detection Results

| Category | Variant | Payload ID | Detector | ML | ML Score | Detected |
|----------|---------|------------|----------|-----|----------|----------|
| character_substitution | char_substitute_symbols | T1535.001 | ✓ | ✗ | 0.0 | ✓ |
| character_substitution | char_substitute_symbols | T1535.002 | ✗ | ✗ | 0.0 | ✗ |
| character_substitution | char_substitute_symbols | T1535.003 | ✗ | ✗ | 0.0 | ✗ |
| character_substitution | char_substitute_symbols | T1535.004 | ✗ | ✗ | 0.0 | ✗ |
| character_substitution | char_substitute_symbols | T1535.005 | ✗ | ✗ | 0.3 | ✗ |
| character_substitution | char_substitute_symbols | T1484.001 | ✗ | ✗ | 0.0 | ✗ |
| character_substitution | char_substitute_symbols | T1484.002 | ✗ | ✗ | 0.0 | ✗ |
| character_substitution | char_substitute_symbols | T1484.003 | ✗ | ✗ | 0.4 | ✗ |
| character_substitution | char_substitute_symbols | T1484.004 | ✗ | ✗ | 0.4 | ✗ |
| character_substitution | char_substitute_symbols | T1484.005 | ✗ | ✗ | 0.0 | ✗ |
| character_substitution | char_substitute_symbols | T1632.001 | ✓ | ✗ | 0.0 | ✓ |
| character_substitution | char_substitute_symbols | T1632.002 | ✗ | ✗ | 0.0 | ✗ |
| character_substitution | char_substitute_symbols | T1632.003 | ✗ | ✗ | 0.0 | ✗ |
| character_substitution | char_substitute_symbols | T1632.004 | ✗ | ✗ | 0.0 | ✗ |
| character_substitution | char_substitute_symbols | T1632.005 | ✗ | ✗ | 0.0 | ✗ |
| character_substitution | char_substitute_symbols | T1589.001 | ✗ | ✗ | 0.0 | ✗ |
| character_substitution | char_substitute_symbols | T1589.002 | ✗ | ✗ | 0.0 | ✗ |
| character_substitution | char_substitute_symbols | T1589.003 | ✓ | ✗ | 0.0 | ✓ |
| character_substitution | char_substitute_symbols | T1589.004 | ✗ | ✗ | 0.0 | ✗ |
| character_substitution | char_substitute_symbols | T1589.005 | ✗ | ✗ | 0.0 | ✗ |
| character_substitution | char_substitute_symbols | T1584.001 | ✓ | ✗ | 0.0 | ✓ |
| character_substitution | char_substitute_symbols | T1584.002 | ✗ | ✗ | 0.0 | ✗ |
| character_substitution | char_substitute_symbols | T1584.003 | ✗ | ✗ | 0.0 | ✗ |
| character_substitution | char_substitute_symbols | T1584.004 | ✗ | ✗ | 0.4 | ✗ |
| character_substitution | char_substitute_symbols | T1584.005 | ✗ | ✗ | 0.0 | ✗ |
| character_substitution | char_substitute_symbols | T1600.001 | ✗ | ✗ | 0.0 | ✗ |
| character_substitution | char_substitute_symbols | T1600.002 | ✓ | ✗ | 0.0 | ✓ |
| character_substitution | char_substitute_symbols | T1600.003 | ✗ | ✗ | 0.0 | ✗ |
| character_substitution | char_substitute_symbols | T1613.001 | ✗ | ✗ | 0.0 | ✗ |
| character_substitution | char_substitute_symbols | T1613.002 | ✗ | ✗ | 0.0 | ✗ |
| ... | ... | ... | ... | ... | ... | ... |

_Showing 30 of 2600 total results_

## Evasion Impact Analysis

- **Baseline detection rate**: 11.5%
- **Evasion detection rate**: 11.7%
- **Detection drop due to evasion**: -1.7%
- **Evasion resistance score**: 11.7/100

> ✅ **GOOD**: Evasion techniques have limited impact on detection.

### Weakest Evasion Categories

1. 🔴 **encoding_evasion**: 3.7% detection [2.4%–5.6%]
2. 🔴 **whitespace_manipulation**: 11.2% detection [8.7%–14.1%]
3. 🔴 **linguistic_obfuscation**: 11.7% detection [9.2%–14.8%]
4. 🔴 **character_substitution**: 12.5% detection [9.9%–15.6%]
5. 🔴 **prompt_fragmentation**: 19.6% detection [16.4%–23.2%]
