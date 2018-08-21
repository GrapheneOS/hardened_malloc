#!/usr/bin/env python3

size_classes = [
    16, 32, 48, 64, 80, 96, 112, 128,
    160, 192, 224, 256,
    320, 384, 448, 512,
    640, 768, 896, 1024,
    1280, 1536, 1792, 2048,
    2560, 3072, 3584, 4096,
    5120, 6144, 7168, 8192,
    10240, 12288, 14336, 16384
]

def page_align(size):
    return (size + 4095) & ~4095

max_bits = 256
max_page_span = 16

print("maximum bitmap size is {}-bit".format(max_bits))
print("maximum page span size is {} ({})".format(max_page_span, max_page_span * 4096))

for size_class in size_classes:
    choices = []
    for bits in range(1, max_bits + 1):
        used = size_class * bits
        real = page_align(used)
        if real > 65536:
            continue
        pages = real / 4096
        efficiency = used / real * 100
        choices.append((bits, used, real, pages, efficiency))

    choices.sort(key=lambda x: x[4], reverse=True)

    print()
    print("size_class:", size_class)
    for choice in choices[:10]:
        print(choice)
