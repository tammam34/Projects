Sender.py:
from scapy.all import *
from custom_proto import CustomProto, encrypt_data
import time

INTERFACE = "eth0"
DEST_MAC = "02:42:ac:11:00:03"
TIMEOUT = 3


def send_frame(seq, message):
    encrypted_data = encrypt_data(message.encode())
    frame = Ether(dst=DEST_MAC, type=0x1234) / CustomProto(
        id=seq,
        msg_type=0,
        data=encrypted_data
    )
    sendp(frame, iface=INTERFACE, verbose=False)
    print(f"[SENDER] Sent frame #{seq}")


def main():
    print("[SENDER] Starting sender...")
    seq = 1

    while True:
        message = input("\nEnter message to send (or 'exit' to quit): ")

        if message.lower() == 'exit':
            print("[SENDER] Exiting...")
            break

        if not message:
            print("[SENDER] Empty message, skipping")
            continue

        while True:
            ack_received = [False]

            def check_ack(pkt):
                if CustomProto in pkt:
                    if pkt[CustomProto].msg_type == 1 and pkt[CustomProto].id == seq:
                        ack_received[0] = True
                        return True
                return False

            sniffer = AsyncSniffer(
                iface=INTERFACE,
                filter="ether proto 0x1234",
                lfilter=check_ack,
                count=1,
                timeout=TIMEOUT
            )

            try:
                sniffer.start()
                time.sleep(0.2)

                send_frame(seq, message)
                print(f"[SENDER] Waiting for ACK #{seq}...")

                start_time = time.time()
                ack_received_flag = False
                while time.time() - start_time < TIMEOUT:
                    if ack_received[0]:
                        print(f"[SENDER] ACK received for frame #{seq}")
                        ack_received_flag = True
                        seq += 1
                        break
                    time.sleep(0.1)

                if not ack_received_flag:
                    print(f"[SENDER] Timeout! No ACK received. Resending frame #{seq}...")
                    continue

            finally:
                try:
                    sniffer.stop()
                except:
                    pass

            break


if __name__ == "__main__":
    main()

Receiver.py:
from scapy.all import *
from custom_proto import CustomProto, decrypt_data

# Configuration
INTERFACE = "eth0"


def send_ack(seq, sender_mac):
    """Send ACK back to sender"""
    try:
        ack_frame = Ether(dst=sender_mac, type=0x1234) / CustomProto(
            id=seq,
            msg_type=1,  # 1 = ACK frame
            data=b'ACK'
        )
        sendp(ack_frame, iface=INTERFACE, verbose=False)
        print(f"[RECEIVER] Sent ACK for frame #{seq}")
    except Exception as e:
        print(f"[RECEIVER] Error sending ACK: {e}")


def handle_frame(pkt):
    """Handle received data frames"""
    try:
        # Check if packet has our custom protocol
        if CustomProto not in pkt:
            return

            # Only process data frames (msg_type = 0)
        if pkt[CustomProto].msg_type != 0:
            return

            # Get sequence number and encrypted data
        seq = pkt[CustomProto].id
        encrypted_data = pkt[CustomProto].data
        sender_mac = pkt.src

        print(f"[RECEIVER] Received frame #{seq} from {sender_mac}")

        try:
            # Decrypt the message
            decrypted_data = decrypt_data(encrypted_data)
            message = decrypted_data.decode()

            # Display received message
            print(f"\n{'=' * 50}")
            print(f"Frame #{seq}")
            print(f"From: {sender_mac}")
            print(f"Message: {message}")
            print(f"{'=' * 50}\n")

        except Exception as e:
            print(f"[RECEIVER] Error decrypting frame #{seq}: {e}")

            # Always send ACK, even if decryption failed
        # (to prevent infinite retransmission)
        send_ack(seq, sender_mac)

    except Exception as e:
        print(f"[RECEIVER] Error handling packet: {e}")


def main():
    print("[RECEIVER] Starting receiver...")
    print(f"[RECEIVER] Listening on interface: {INTERFACE}")
    print(f"[RECEIVER] Waiting for frames...\n")

    try:
        # Start sniffing for frames
        sniff(
            iface=INTERFACE,
            filter="ether proto 0x1234",
            prn=handle_frame,
            store=False  # Don't store packets in memory
        )
    except KeyboardInterrupt:
        print("\n[RECEIVER] Stopped by user")
    except Exception as e:
        print(f"[RECEIVER] Error: {e}")


if __name__ == "__main__":
    main()

Observer.py:
from scapy.all import *
from custom_proto import CustomProto

INTERFACE = "eth0"


def handle_packet(pkt):
    if CustomProto not in pkt:
        return


seq = pkt[CustomProto].id
msg_type = pkt[CustomProto].msg_type
src_mac = pkt.src
dst_mac = pkt.dst
if msg_type == 0:
    print(f"DATA frame #{seq}: {src_mac} -> {dst_mac}")
else:
    print(f"ACK frame #{seq}: {src_mac} -> {dst_mac}")


def main():
    print("[OBSERVER] Listening...")


try:
    sniff(
        iface=INTERFACE,
        filter="ether proto 0x1234",
        prn=handle_packet,
        store=False
    )
except KeyboardInterrupt:
    print("\n[OBSERVER] Stopped")
if __name__ == "__main__":
    main()

Custom_proto.py:
from scapy.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

SECRET_KEY = b'1234567890abcdef'


def encrypt_data(data: bytes) -> bytes:
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(data, AES.block_size))


def decrypt_data(data: bytes) -> bytes:
    cipher = AES.new(SECRET_KEY, AES.MODE_ECB)
    return unpad(cipher.decrypt(data), AES.block_size)


class CustomProto(Packet):
    name = "CustomProto"
    fields_desc = [
        ShortField("id", 0),
        ByteField("msg_type", 0),
        FieldLenField("len", None, length_of="payload", fmt="H"),
        StrLenField("payload", "", length_from=lambda pkt: pkt.len)
    ]


bind_layers(Ether, CustomProto, type=0x1234)