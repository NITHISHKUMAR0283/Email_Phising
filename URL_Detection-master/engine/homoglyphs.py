"""
Homograph Attack Detection Data
================================
Character substitution maps for detecting visual spoofing attacks.
"""

# Cyrillic characters that look like Latin
CYRILLIC_TO_LATIN = {
    '\u0430': 'a',  # а → a
    '\u0435': 'e',  # е → e
    '\u043e': 'o',  # о → o
    '\u0440': 'p',  # р → p
    '\u0441': 'c',  # с → c
    '\u0443': 'y',  # у → y
    '\u0445': 'x',  # х → x
    '\u043a': 'k',  # к → k
    '\u043c': 'm',  # м → m
    '\u0442': 't',  # т → t
    '\u0456': 'i',  # і → i
    '\u0458': 'j',  # ј → j
    '\u0455': 's',  # ѕ → s
    '\u0432': 'b',  # в → b (visual)
    '\u043d': 'h',  # н → h
}

# Greek characters that look like Latin
GREEK_TO_LATIN = {
    '\u03b1': 'a',  # α → a
    '\u03b2': 'b',  # β → b
    '\u03b5': 'e',  # ε → e
    '\u03bf': 'o',  # ο → o
    '\u03c1': 'p',  # ρ → p
    '\u03c4': 't',  # τ → t
    '\u03ba': 'k',  # κ → k
    '\u03bd': 'v',  # ν → v
    '\u03c5': 'u',  # υ → u
    '\u03b9': 'i',  # ι → i
}

# Visual lookalikes (ASCII-range confusables)
VISUAL_LOOKALIKES = {
    '0': 'o',
    '1': 'l',
    'l': 'i',
    'I': 'l',
    '|': 'l',
}

# Combined mapping for detection
ALL_HOMOGLYPHS = {}
ALL_HOMOGLYPHS.update(CYRILLIC_TO_LATIN)
ALL_HOMOGLYPHS.update(GREEK_TO_LATIN)

# Multi-character visual tricks
MULTI_CHAR_TRICKS = {
    'rn': 'm',
    'vv': 'w',
    'cl': 'd',
    'nn': 'nn',  # can look like m in some fonts
}

# Keyboard walk patterns
KEYBOARD_WALKS = [
    'qwerty', 'qwertz', 'asdfgh', 'zxcvbn', 'qazwsx',
    'wsxedc', 'rfvtgb', 'yhnujm', '123456', '654321',
    'abcdef', 'asdfjkl',
]


def normalize_homoglyphs(text: str) -> str:
    """Replace homoglyph characters with their Latin equivalents."""
    result = []
    for char in text:
        if char in ALL_HOMOGLYPHS:
            result.append(ALL_HOMOGLYPHS[char])
        else:
            result.append(char)
    return ''.join(result)


def detect_homoglyphs(text: str) -> list:
    """Detect any homoglyph characters in the text. Returns list of found homoglyphs."""
    found = []
    for i, char in enumerate(text):
        if char in ALL_HOMOGLYPHS:
            found.append({
                'position': i,
                'character': char,
                'unicode': f'U+{ord(char):04X}',
                'looks_like': ALL_HOMOGLYPHS[char],
                'script': 'Cyrillic' if char in CYRILLIC_TO_LATIN else 'Greek'
            })
    return found


def check_multi_char_tricks(text: str) -> list:
    """Detect multi-character visual tricks like 'rn' → 'm'."""
    found = []
    for trick, looks_like in MULTI_CHAR_TRICKS.items():
        if trick in text:
            found.append({
                'sequence': trick,
                'looks_like': looks_like,
                'position': text.index(trick)
            })
    return found


def check_keyboard_walks(text: str) -> bool:
    """Check if the domain contains keyboard walk patterns."""
    text_lower = text.lower()
    for walk in KEYBOARD_WALKS:
        if walk in text_lower:
            return True
    return False
