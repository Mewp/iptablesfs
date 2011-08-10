files = {
    'rules': {
        'exclude': r'^-[PN]',
        'hide': [r'^-[AI] \w+ ']
    },
    'policy': {
        'exists': lambda fs, table, chain: fs.chains[table][chain]['built-in'],
        'match': r'^-P',
        'chain_option': 'P',
        'hide': [r'^-P \w+ ']
    },
    'tcp': {
        'match': r'-p tcp',
        'hide': [r'^-[AI] \w+ ', r'\s*-[pm] tcp\s*'],
        'prepend': '-p tcp'
    },
    'udp': {
        'match': r'-p udp',
        'hide': [r'^-[AI] \w+ ', r'\s*-[pm] udp\s*'],
        'prepend': '-p udp'
    },
    'DROP': {
        'match': r'-j DROP',
        'hide': [r'^-[AI] \w+ ', r'\s*-j DROP\s*'],
        'append': '-j DROP'
    },
    'ACCEPT': {
        'match': r'-j ACCEPT',
        'hide': [r'^-[AI] \w+ ', r'\s*-j ACCEPT\s*'],
        'append': '-j ACCEPT'
    },
    'REJECT': {
        'match': r'-j REJECT',
        'hide': [r'^-[AI] \w+ ', r'\s*-j REJECT\s*'],
        'append': '-j REJECT'
    },
    'MASQUERADE': {
        'exists': lambda fs, table, chain: table == 'nat' and chain == 'POSTROUTING',
        'match': r'-j MASQUERADE',
        'hide': [r'^-[AI] \w+ ', r'-j MASQUERADE\s*', r'-o\s*'],
        'prepend': '-o ',
        'append': '-j MASQUERADE'
    },
}
