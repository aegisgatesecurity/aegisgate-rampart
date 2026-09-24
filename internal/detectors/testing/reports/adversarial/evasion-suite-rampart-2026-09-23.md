# AegisGate Rampart — Adversarial Evasion Suite

**Timestamp**: 2026-09-23T19:24:25-05:00  
**Suite Phase**: rampart-0a  
**Go Version**: 1.26  

## Overall Evasion Resistance

| Metric | Value |
|--------|-------|
| Total Tests | 4050 |
| Total Detected | 4014 |
| Raw Detection Rate | 99.1% |
| Weighted Detection Rate | 99.1% |
| **Evasion Resistance Score** | **99.1/100** |
| 95% Wilson CI | [98.8%–99.4%] |

## Baseline (Unmodified Payloads)

| Metric | Value |
|--------|-------|
| Total Payloads | 81 |
| Detected | 80 |
| Detection Rate | 98.8% |
| 95% Wilson CI | [93.3%–99.8%] |

## Per-Category Results

| Category | Variants | Tests | Detected | Detection Rate | 95% CI |
|----------|----------|-------|----------|-----------------|--------|
| character_substitution | 10 | 810 | 798 | 98.5% | [97.4%–99.2%] |
| encoding_evasion | 10 | 810 | 802 | 99.0% | [98.1%–99.5%] |
| linguistic_obfuscation | 10 | 810 | 805 | 99.4% | [98.6%–99.7%] |
| whitespace_manipulation | 10 | 810 | 800 | 98.8% | [97.7%–99.3%] |
| prompt_fragmentation | 10 | 810 | 809 | 99.9% | [99.3%–100.0%] |

## Per-Variant Breakdown

### character_substitution

| Variant | Total | Detected | Rate |
|---------|-------|----------|------|
| char_delete_vowels | 81 | 78 | 96.3% |
| char_transpose_adjacent | 81 | 80 | 98.8% |
| keyboard_walk_shift | 81 | 80 | 98.8% |
| char_repeat | 81 | 80 | 98.8% |
| char_reverse_words | 81 | 80 | 98.8% |
| l33t_common | 81 | 80 | 98.8% |
| char_insert_hyphens | 81 | 80 | 98.8% |
| l33t_aggressive | 81 | 80 | 98.8% |
| char_insert_dots | 81 | 80 | 98.8% |
| char_substitute_symbols | 81 | 80 | 98.8% |

### encoding_evasion

| Variant | Total | Detected | Rate |
|---------|-------|----------|------|
| html_entity_encode | 81 | 80 | 98.8% |
| backslash_escape | 81 | 80 | 98.8% |
| unicode_escapes | 81 | 80 | 98.8% |
| base64_prefix | 81 | 81 | 100.0% |
| base64_full | 81 | 81 | 100.0% |
| rot13_partial | 81 | 80 | 98.8% |
| url_encode_spaces | 81 | 80 | 98.8% |
| mixed_encoding | 81 | 80 | 98.8% |
| url_encode_keywords | 81 | 80 | 98.8% |
| hex_escape_encode | 81 | 80 | 98.8% |

### linguistic_obfuscation

| Variant | Total | Detected | Rate |
|---------|-------|----------|------|
| story_framing | 81 | 81 | 100.0% |
| sentence_restructure | 81 | 80 | 98.8% |
| polite_wrapper | 81 | 81 | 100.0% |
| academic_tone | 81 | 80 | 98.8% |
| indirect_phrasing | 81 | 81 | 100.0% |
| passive_voice | 81 | 80 | 98.8% |
| negation_inversion | 81 | 80 | 98.8% |
| definition_bypass | 81 | 81 | 100.0% |
| synonym_substitution | 81 | 80 | 98.8% |
| hypothetical_framing | 81 | 81 | 100.0% |

### whitespace_manipulation

| Variant | Total | Detected | Rate |
|---------|-------|----------|------|
| unicode_invisible | 81 | 80 | 98.8% |
| zero_width_joiner | 81 | 80 | 98.8% |
| zero_width_nonjoiner | 81 | 80 | 98.8% |
| extra_spaces | 81 | 80 | 98.8% |
| zero_width_space | 81 | 80 | 98.8% |
| line_break_scatter | 81 | 80 | 98.8% |
| mixed_whitespace | 81 | 80 | 98.8% |
| tab_insertion | 81 | 80 | 98.8% |
| double_spaces | 81 | 80 | 98.8% |
| word_split_newline | 81 | 80 | 98.8% |

### prompt_fragmentation

| Variant | Total | Detected | Rate |
|---------|-------|----------|------|
| encoded_boundary | 81 | 81 | 100.0% |
| system_prefix | 81 | 81 | 100.0% |
| markdown_headers | 81 | 81 | 100.0% |
| role_delimiter | 81 | 81 | 100.0% |
| nested_instruction | 81 | 81 | 100.0% |
| split_half | 81 | 81 | 100.0% |
| split_triples | 81 | 80 | 98.8% |
| concatenation_hint | 81 | 81 | 100.0% |
| progressive_disclosure | 81 | 81 | 100.0% |
| context_boundary | 81 | 81 | 100.0% |

## Sample Detection Results

| Category | Variant | Payload ID | Detector | ML | ML Score | Detected |
|----------|---------|------------|----------|-----|----------|----------|
| character_substitution | l33t_common | T1535.001 | ✓ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1535.002 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1535.003 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1535.004 | ✓ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1535.005 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1484.001 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1484.002 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1484.003 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1484.004 | ✓ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1484.005 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1632.001 | ✓ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1632.002 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1632.003 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1632.004 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1632.005 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1589.001 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1589.002 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1589.003 | ✓ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1589.004 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1589.005 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1584.001 | ✓ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1584.002 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1584.003 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1584.004 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1584.005 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1600.001 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1600.002 | ✓ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1600.003 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1613.001 | ✗ | ✓ | 1.0 | ✓ |
| character_substitution | l33t_common | T1613.002 | ✗ | ✓ | 1.0 | ✓ |
| ... | ... | ... | ... | ... | ... | ... |

_Showing 30 of 4050 total results_

## Evasion Impact Analysis

- **Baseline detection rate**: 98.8%
- **Evasion detection rate**: 99.1%
- **Detection drop due to evasion**: -0.3%
- **Evasion resistance score**: 99.1/100

> ✅ **GOOD**: Evasion techniques have limited impact on detection.

### Weakest Evasion Categories

1. 🟢 **character_substitution**: 98.5% detection [97.4%–99.2%]
2. 🟢 **whitespace_manipulation**: 98.8% detection [97.7%–99.3%]
3. 🟢 **encoding_evasion**: 99.0% detection [98.1%–99.5%]
4. 🟢 **linguistic_obfuscation**: 99.4% detection [98.6%–99.7%]
5. 🟢 **prompt_fragmentation**: 99.9% detection [99.3%–100.0%]
