#!/usr/bin/env python3
"""
Script para migrar logging statements de cout/cerr a Logger en Node.cpp
"""

import re
import sys

def migrate_logging(content):
    """Migra cout/cerr a Logger calls"""
    
    # Pattern 1: Simple cout with string and endl
    content = re.sub(
        r'std::cout\s*<<\s*"([^"]+)"\s*<<\s*std::endl;',
        r'LOG_INFO(Logger::network(), "\1");',
        content
    )
    
    # Pattern 2: Simple cerr with string and endl
    content = re.sub(
        r'std::cerr\s*<<\s*"([^"]+)"\s*<<\s*std::endl;',
        r'LOG_ERROR(Logger::network(), "\1");',
        content
    )
    
    # Pattern 3: cout with one variable
    content = re.sub(
        r'std::cout\s*<<\s*"([^"]+)"\s*<<\s*(\w+(?:->\w+\(\))?)\s*<<\s*std::endl;',
        r'LOG_INFO(Logger::network(), "\1{}", \2);',
        content
    )
    
    # Pattern 4: cerr with one variable
    content = re.sub(
        r'std::cerr\s*<<\s*"([^"]+)"\s*<<\s*(\w+(?:->\w+\(\))?|e\.what\(\))\s*<<\s*std::endl;',
        r'LOG_ERROR(Logger::network(), "\1{}", \2);',
        content
    )
    
    # Pattern 5: cout with multiple parts (complex)
    # Example: std::cout << "Value: " << val << " Text: " << text << std::endl;
    def replace_complex(match):
        full = match.group(0)
        parts = re.findall(r'<<\s*([^<]+)', full)
        
        msg = ""
        args = []
        for part in parts[1:-1]:  # Skip first << and last std::endl
            part = part.strip().strip('"')
            if part.startswith('"') or part.endswith('"'):
                msg += part.strip('"')
            else:
                msg += "{}"
                args.append(part)
        
        if "std::cout" in full:
            if args:
                return f'LOG_INFO(Logger::network(), "{msg}", {", ".join(args)});'
            else:
                return f'LOG_INFO(Logger::network(), "{msg}");'
        else:
            if args:
                return f'LOG_ERROR(Logger::network(), "{msg}", {", ".join(args)});'
            else:
                return f'LOG_ERROR(Logger::network(), "{msg}");'
    
    # Apply complex pattern carefully
    content = re.sub(
        r'std::(?:cout|cerr)\s*<<.*?<<\s*std::endl;',
        replace_complex,
        content
    )
    
    return content

def main():
    file_path = "src/networking/Node.cpp"
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        migrated = migrate_logging(content)
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(migrated)
        
        print(f"✓ Migration completed for {file_path}")
        
    except Exception as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
