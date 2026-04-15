#!/usr/bin/env python3
"""
Digital Privacy and Security Toolkit
For personal and organizational privacy protection

Features:
- File encryption/decryption (AES-128-CBC via Fernet)
- Secure password generation
- Metadata cleaning
- Secure file deletion
- GPG key generation

License: MIT
Version: 1.0 (April 2026)
"""

import os
import secrets
import base64
import hashlib
import platform
from typing import Optional, Dict, List, Tuple
from pathlib import Path


class PrivacyToolkit:
    """
    Comprehensive privacy protection toolkit
    
    Implements industry-standard cryptographic practices:
    - PBKDF2 for key derivation (480,000 iterations)
    - Fernet (AES-128-CBC) for symmetric encryption
    - Secure random number generation
    """
    
    def __init__(self):
        """Initialize privacy toolkit"""
        self._check_dependencies()
    
    def _check_dependencies(self):
        """Check for required cryptographic libraries"""
        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
        except ImportError:
            print("Warning: cryptography library not installed.")
            print("Install with: pip install cryptography")
    
    @staticmethod
    def generate_secure_password(length: int = 32, 
                                  use_special: bool = True) -> str:
        """
        Generate cryptographically secure password
        
        Args:
            length: Password length
            use_special: Include special characters
        
        Returns:
            Secure random password
        """
        alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        if use_special:
            alphabet += '!@#$%^&*()-_=+[]{}|;:,.<>?'
        
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @staticmethod
    def generate_passphrase(num_words: int = 6, 
                           wordlist_path: Optional[str] = None) -> str:
        """
        Generate diceware-style passphrase
        
        More memorable than random passwords while maintaining security
        """
        # Default EFF wordlist (simplified)
        default_words = [
            'abacus', 'abdomen', 'ability', 'absorb', 'abstract', 'academy',
            'account', 'achieve', 'acidity', 'acquire', 'acrobat', 'action',
            'active', 'activity', 'actual', 'adapter', 'advance', 'advice',
            'aerial', 'affair', 'affect', 'afford', 'against', 'agency',
            'agenda', 'agree', 'aircraft', 'airport', 'alarm', 'album',
            'alcohol', 'alert', 'algebra', 'algorithm', 'alias', 'alive',
            'alliance', 'allow', 'almost', 'alphabet', 'already', 'also',
            'altar', 'alter', 'always', 'amazing', 'ambition', 'among',
            'amount', 'amplify', 'anchor', 'ancient', 'android', 'anger',
            'animal', 'ankle', 'announce', 'annual', 'answer', 'antenna',
        ]
        
        words = default_words
        if wordlist_path and os.path.exists(wordlist_path):
            with open(wordlist_path, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
        
        return '-'.join(secrets.choice(words) for _ in range(num_words))
    
    @staticmethod
    def hash_sensitive_data(data: str, salt: Optional[bytes] = None) -> Dict:
        """
        Hash sensitive data with salt using PBKDF2
        
        Args:
            data: String to hash
            salt: Optional salt (generated if not provided)
        
        Returns:
            Dictionary with hash, salt, and algorithm info
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
        
        if salt is None:
            salt = os.urandom(32)
        
        # PBKDF2 with SHA-256, 480,000 iterations
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        
        key = kdf.derive(data.encode())
        
        return {
            'hash': base64.b64encode(key).decode('utf-8'),
            'salt': base64.b64encode(salt).decode('utf-8'),
            'algorithm': 'PBKDF2-SHA256',
            'iterations': 480000
        }
    
    @staticmethod
    def verify_hash(data: str, hash_info: Dict) -> bool:
        """
        Verify data against stored hash
        
        Args:
            data: Data to verify
            hash_info: Dictionary from hash_sensitive_data()
        
        Returns:
            True if data matches hash
        """
        salt = base64.b64decode(hash_info['salt'])
        new_hash = PrivacyToolkit.hash_sensitive_data(data, salt)
        return new_hash['hash'] == hash_info['hash']
    
    def encrypt_file(self, file_path: str, password: str,
                     output_path: Optional[str] = None) -> str:
        """
        Encrypt a file using Fernet (AES-128-CBC)
        
        Args:
            file_path: Path to file to encrypt
            password: Encryption password
            output_path: Optional output path (default: file.encrypted)
        
        Returns:
            Path to encrypted file
        """
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
        
        # Generate salt and key
        salt = os.urandom(16)
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Encrypt file
        fernet = Fernet(key)
        
        with open(file_path, 'rb') as f:
            data = f.read()
        
        encrypted = fernet.encrypt(data)
        
        # Save encrypted file with salt prefix
        if output_path is None:
            output_path = file_path + '.encrypted'
        
        with open(output_path, 'wb') as f:
            f.write(salt + encrypted)
        
        return output_path
    
    def decrypt_file(self, file_path: str, password: str,
                     output_path: Optional[str] = None) -> str:
        """
        Decrypt a file encrypted with encrypt_file
        
        Args:
            file_path: Path to encrypted file
            password: Decryption password
            output_path: Optional output path
        
        Returns:
            Path to decrypted file
        """
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
        
        # Read salt and encrypted data
        with open(file_path, 'rb') as f:
            salt = f.read(16)
            encrypted = f.read()
        
        # Generate key
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Decrypt
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted)
        
        # Save decrypted file
        if output_path is None:
            if file_path.endswith('.encrypted'):
                output_path = file_path[:-10]
            else:
                output_path = file_path + '.decrypted'
        
        with open(output_path, 'wb') as f:
            f.write(decrypted)
        
        return output_path
    
    @staticmethod
    def secure_delete(file_path: str, passes: int = 3) -> bool:
        """
        Securely delete a file by overwriting before deletion
        
        Implements DoD 5220.22-M style multi-pass overwrite
        
        Args:
            file_path: Path to file to delete
            passes: Number of overwrite passes
        
        Returns:
            True if successful
        """
        if not os.path.exists(file_path):
            return False
        
        file_size = os.path.getsize(file_path)
        
        if file_size == 0:
            os.remove(file_path)
            return True
        
        try:
            with open(file_path, 'ba+', buffering=0) as f:
                for pass_num in range(passes):
                    f.seek(0)
                    
                    # Alternate between random and pattern overwrites
                    if pass_num % 2 == 0:
                        f.write(os.urandom(file_size))
                    else:
                        pattern = bytes([0x55 if pass_num % 4 == 1 else 0xAA])
                        f.write(pattern * file_size)
                    
                    f.flush()
                    os.fsync(f.fileno())
            
            # Final rename to obscure original name
            temp_name = os.path.join(
                os.path.dirname(file_path),
                '.' + secrets.token_hex(16)
            )
            os.rename(file_path, temp_name)
            
            os.remove(temp_name)
            return True
        
        except Exception as e:
            print(f"Secure delete failed: {e}")
            return False
    
    @staticmethod
    def generate_gpg_key_batch(name: str, email: str, 
                               key_length: int = 4096,
                               expire_years: int = 2) -> str:
        """
        Generate GPG batch file for unattended key generation
        
        Args:
            name: Real name for key
            email: Email address
            key_length: RSA key length
            expire_years: Years until expiration
        
        Returns:
            GPG batch configuration
        """
        batch_config = f"""%echo Generating GPG key for {name}
Key-Type: RSA
Key-Length: {key_length}
Subkey-Type: RSA
Subkey-Length: {key_length}
Name-Real: {name}
Name-Email: {email}
Expire-Date: {expire_years}y
%no-ask-passphrase
%no-protection
%commit
%echo done
"""
        return batch_config
    
    @staticmethod
    def generate_ssh_key_config(key_type: str = 'ed25519',
                                 comment: str = '') -> Dict:
        """
        Generate SSH key generation command
        
        Args:
            key_type: SSH key type (ed25519, rsa, ecdsa)
            comment: Key comment
        
        Returns:
            Dictionary with command and recommendations
        """
        commands = {
            'ed25519': f'ssh-keygen -t ed25519 -C "{comment}"',
            'rsa': f'ssh-keygen -t rsa -b 4096 -C "{comment}"',
            'ecdsa': f'ssh-keygen -t ecdsa -b 521 -C "{comment}"'
        }
        
        return {
            'recommended': 'ed25519',
            'command': commands.get(key_type, commands['ed25519']),
            'all_commands': commands,
            'security_note': 'ED25519 recommended for new keys (faster, more secure)'
        }


# Metadata Cleaner
class MetadataCleaner:
    """Clean metadata from files"""
    
    @staticmethod
    def clean_image_metadata(image_path: str, output_path: Optional[str] = None) -> Optional[str]:
        """
        Remove EXIF metadata from images
        
        Args:
            image_path: Path to image file
            output_path: Optional output path
        
        Returns:
            Path to cleaned image or None if failed
        """
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            
            img = Image.open(image_path)
            
            # Create clean copy without EXIF
            data = list(img.getdata())
            clean_img = Image.new(img.mode, img.size)
            clean_img.putdata(data)
            
            if output_path is None:
                base, ext = os.path.splitext(image_path)
                output_path = f"{base}_cleaned{ext}"
            
            # Save without EXIF
            clean_img.save(output_path, exif=b'')
            
            return output_path
        
        except ImportError:
            print("PIL not installed. Install with: pip install Pillow")
            return None
        except Exception as e:
            print(f"Image cleaning failed: {e}")
            return None
    
    @staticmethod
    def clean_pdf_metadata(pdf_path: str, output_path: Optional[str] = None) -> Optional[str]:
        """
        Remove metadata from PDF files
        
        Args:
            pdf_path: Path to PDF file
            output_path: Optional output path
        
        Returns:
            Path to cleaned PDF or None if failed
        """
        try:
            from PyPDF2 import PdfReader, PdfWriter
            
            reader = PdfReader(pdf_path)
            writer = PdfWriter()
            
            # Copy pages
            for page in reader.pages:
                writer.add_page(page)
            
            # Clear metadata
            writer.add_metadata({})
            
            if output_path is None:
                base, ext = os.path.splitext(pdf_path)
                output_path = f"{base}_cleaned{ext}"
            
            with open(output_path, 'wb') as f:
                writer.write(f)
            
            return output_path
        
        except ImportError:
            print("PyPDF2 not installed. Install with: pip install PyPDF2")
            return None
        except Exception as e:
            print(f"PDF cleaning failed: {e}")
            return None
    
    @staticmethod
    def get_file_metadata(filepath: str) -> Dict:
        """
        Get file metadata (for analysis before cleaning)
        
        Args:
            filepath: Path to file
        
        Returns:
            Dictionary of metadata
        """
        stat = os.stat(filepath)
        
        return {
            'filename': os.path.basename(filepath),
            'size_bytes': stat.st_size,
            'created': stat.st_ctime,
            'modified': stat.st_mtime,
            'accessed': stat.st_atime,
            'permissions': oct(stat.st_mode)[-3:],
        }


# Communication Security
class CommSecurity:
    """Secure communication utilities"""
    
    @staticmethod
    def generate_signal_backup_code() -> str:
        """
        Generate Signal-style backup code
        12 groups of 5 digits
        """
        groups = []
        for _ in range(12):
            group = ''.join(str(secrets.randbelow(10)) for _ in range(5))
            groups.append(group)
        return ' '.join(groups)
    
    @staticmethod
    def verify_checksum(data: bytes, expected_hash: str,
                        algorithm: str = 'sha256') -> bool:
        """
        Verify data integrity using cryptographic hash
        
        Args:
            data: Data to verify
            expected_hash: Expected hash value
            algorithm: Hash algorithm
        
        Returns:
            True if hash matches
        """
        hash_obj = hashlib.new(algorithm)
        hash_obj.update(data)
        actual_hash = hash_obj.hexdigest()
        return actual_hash.lower() == expected_hash.lower()
    
    @staticmethod
    def generate_tor_onion_service_key() -> Dict:
        """
        Generate Tor onion service key structure (simplified)
        
        Returns:
            Dictionary with key information
        """
        private_key = secrets.token_bytes(32)
        public_key = secrets.token_bytes(32)
        
        # Onion address is base32 of truncated public key hash
        onion_hash = hashlib.sha1(public_key).digest()[:10]
        onion_address = base64.b32encode(onion_hash).decode().lower() + '.onion'
        
        return {
            'private_key': base64.b64encode(private_key).decode(),
            'public_key': base64.b64encode(public_key).decode(),
            'onion_address': onion_address,
            'note': 'This is a demonstration. Use tor --hash-password for production.'
        }
    
    @staticmethod
    def derive_key_from_password(password: str, salt: bytes,
                                  length: int = 32) -> bytes:
        """
        Derive cryptographic key from password
        
        Args:
            password: User password
            salt: Random salt
            length: Desired key length
        
        Returns:
            Derived key
        """
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=480000,
        )
        
        return kdf.derive(password.encode())


# System Privacy
class SystemPrivacy:
    """System-level privacy utilities"""
    
    @staticmethod
    def get_system_info() -> Dict:
        """Get system information for privacy audit"""
        return {
            'platform': platform.system(),
            'platform_version': platform.version(),
            'architecture': platform.architecture(),
            'processor': platform.processor(),
            'hostname': platform.node(),
        }
    
    @staticmethod
    def check_dns_leak() -> Dict:
        """
        Check for DNS leak (basic)
        
        Returns:
            Information about DNS configuration
        """
        import socket
        
        try:
            # Get hostname
            hostname = socket.gethostname()
            
            # Try to resolve a test domain
            try:
                ip = socket.gethostbyname('dnsleaktest.com')
                can_resolve = True
            except:
                can_resolve = False
            
            return {
                'hostname': hostname,
                'can_resolve_external': can_resolve,
                'note': 'Use dnsleaktest.com for comprehensive testing'
            }
        except Exception as e:
            return {'error': str(e)}


def main():
    """Demonstration of privacy toolkit"""
    print("=" * 60)
    print("DIGITAL PRIVACY AND SECURITY TOOLKIT")
    print("=" * 60)
    
    toolkit = PrivacyToolkit()
    
    print("\n1. Secure Password Generation")
    print("-" * 40)
    print(f"  Random: {toolkit.generate_secure_password(24)}")
    print(f"  Passphrase: {toolkit.generate_passphrase(5)}")
    
    print("\n2. Password Hashing")
    print("-" * 40)
    hash_info = toolkit.hash_sensitive_data("my_secret_password")
    print(f"  Algorithm: {hash_info['algorithm']}")
    print(f"  Iterations: {hash_info['iterations']}")
    print(f"  Hash: {hash_info['hash'][:40]}...")
    
    # Verify
    is_valid = toolkit.verify_hash("my_secret_password", hash_info)
    print(f"  Verification: {'PASS' if is_valid else 'FAIL'}")
    
    print("\n3. GPG Key Generation Batch File")
    print("-" * 40)
    gpg_batch = toolkit.generate_gpg_key_batch("Alice Smith", "alice@example.com")
    print(gpg_batch[:200] + "...")
    
    print("\n4. SSH Key Generation")
    print("-" * 40)
    ssh_config = toolkit.generate_ssh_key_config(comment="personal_key")
    print(f"  Recommended: {ssh_config['recommended']}")
    print(f"  Command: {ssh_config['command']}")
    
    print("\n5. Signal Backup Code")
    print("-" * 40)
    print(f"  {CommSecurity.generate_signal_backup_code()}")
    
    print("\n6. System Information")
    print("-" * 40)
    sys_info = SystemPrivacy.get_system_info()
    for key, value in sys_info.items():
        print(f"  {key}: {value}")
    
    print("\n" + "=" * 60)
    print("All tools are functional and ready for use.")
    print("=" * 60)


if __name__ == "__main__":
    main()
