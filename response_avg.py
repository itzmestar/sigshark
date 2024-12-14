import pyshark
import pandas as pd
from scapy.all import PcapReader, PcapWriter
import io
import os
import tempfile


class ProcessPCAP:
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.capture = pyshark.FileCapture(pcap_file, keep_packets=False)
        print("PCAP file loaded.")
        self.transactions = []

    @staticmethod
    def extract_transaction_id(packet, protocol):
        # Implement transaction ID extraction based on protocol fields
        if protocol == 'TCAP':
            # print(dir(packet.tcap))
            # print(packet.tcap.field_names)
            if hasattr(packet.tcap, 'tid'):
                return packet.tcap.tid

        elif protocol == 'SS7-MAP':
            # Assuming SS7-MAP specific field extraction (e.g., TCAP Transaction ID)
            if hasattr(packet.ss7map, 'transaction_id'):
                return packet.ss7map.transaction_id
        elif protocol == 'Diameter':
            # Diameter specific Session-ID extraction
            if hasattr(packet.diameter, 'session_id'):
                return packet.diameter.session_id
        return "UnknownTransactionID"

    @staticmethod
    def extract_message_type(packet, protocol):
        # Determine if the message is a Request or Response based on protocol-specific fields
        if protocol == 'TCAP':
            # Map TCAP message type to Request/Response
            if hasattr(packet.tcap, 'begin_element'):
                return 'Request'
            elif hasattr(packet.tcap, 'end_element'):
                return 'Response'
            else:
                return 'Response'
        elif protocol == 'SS7-MAP':
            # Assuming SS7-MAP message type extraction
            if hasattr(packet.ss7map, 'msg_type'):
                return packet.ss7map.msg_type
        elif protocol == 'Diameter':
            # Diameter message type extraction (e.g., Request/Response Command Code)
            if hasattr(packet.diameter, 'command_code'):
                return "Request" if 'Request' in str(packet.diameter.command_code) else "Response"
        return "UnknownMessageType"

    def process_pcap(self):
        i = 1
        for packet in self.capture:
            if i % 1000 == 0:
                print(f"Processed {i} packets")
            try:
                # Extract timestamp
                timestamp = float(packet.sniff_timestamp)

                # Check protocol
                # Check for TCAP layer
                if hasattr(packet, 'tcap'):
                    protocol = 'TCAP'
                    transaction_id = self.extract_transaction_id(packet, protocol)
                    msg_type = self.extract_message_type(packet, protocol)

                elif hasattr(packet, 'ss7map'):  # SS7-MAP specific layer
                    protocol = 'SS7-MAP'
                    transaction_id = self.extract_transaction_id(packet, protocol)
                    msg_type = self.extract_message_type(packet, protocol)

                elif hasattr(packet, 'diameter'):  # Diameter specific layer
                    protocol = 'Diameter'
                    transaction_id = self.extract_transaction_id(packet, protocol)
                    msg_type = self.extract_message_type(packet, protocol)

                else:
                    # print(packet)
                    continue

                self.transactions.append({
                    'timestamp': timestamp,
                    'protocol': protocol,
                    'transaction_id': transaction_id,
                    'msg_type': msg_type,
                })
            except Exception as e:
                print(f"Error parsing packet: {e}")
            i += 1

    def workflow(self):
        self.process_pcap()


# Define lists to store extracted data
transactions = []

def process_large_pcap(file_path):
    i = 1
    with PcapReader(file_path) as pcap_reader:
        for pkt in pcap_reader:
            if i % 100 == 0:
                print(f"Processed {i} packets")
            raw_bytes = bytes(pkt)
            parse_pcap(raw_bytes)
            i += 1
            if i == 15:
                return

def parse_pcap(packet_bytes):
    # Create a pseudo PCAP file in memory for Pyshark
    #pcap_stream = io.BytesIO()
    #pcap_stream.write(packet_bytes)
    #pcap_stream.seek(0)

    # Create a temporary PCAP file to store the raw packet
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as temp_pcap_file:
        temp_file_path = temp_pcap_file.name

        # Write the Scapy packet to the file with the appropriate link-layer type
        with PcapWriter(temp_file_path, append=True, sync=True, linktype=1) as writer:  # Type 1 = Ethernet
            writer.write(packet_bytes)

    # Read the PCAP file using Pyshark
    capture = pyshark.FileCapture(temp_file_path)

    for packet in capture:
        try:
            # Extract timestamp
            timestamp = float(packet.sniff_timestamp)

            # Check protocol
            # Check for TCAP layer
            if hasattr(packet, 'tcap'):
                protocol = 'TCAP'
                transaction_id = extract_transaction_id(packet, protocol)
                msg_type = extract_message_type(packet, protocol)

            elif hasattr(packet, 'ss7map'):  # SS7-MAP specific layer
                protocol = 'SS7-MAP'
                transaction_id = extract_transaction_id(packet, protocol)
                msg_type = extract_message_type(packet, protocol)

            elif hasattr(packet, 'diameter'):  # Diameter specific layer
                protocol = 'Diameter'
                transaction_id = extract_transaction_id(packet, protocol)
                msg_type = extract_message_type(packet, protocol)

            else:
                #print(packet)
                continue

            transactions.append({
                'timestamp': timestamp,
                'protocol': protocol,
                'transaction_id': transaction_id,
                'msg_type': msg_type,
            })
        except Exception as e:
            print(f"Error parsing packet: {e}")

    capture.close()
    os.remove(temp_file_path)
    #return pd.DataFrame(transactions)

def extract_transaction_id(packet, protocol):
    # Implement transaction ID extraction based on protocol fields
    if protocol == 'TCAP':
        #print(dir(packet.tcap))
        #print(packet.tcap.field_names)
        if hasattr(packet.tcap, 'tid'):
            return packet.tcap.tid

    elif protocol == 'SS7-MAP':
        # Assuming SS7-MAP specific field extraction (e.g., TCAP Transaction ID)
        if hasattr(packet.ss7map, 'transaction_id'):
            return packet.ss7map.transaction_id
    elif protocol == 'Diameter':
        # Diameter specific Session-ID extraction
        if hasattr(packet.diameter, 'session_id'):
            return packet.diameter.session_id
    return "UnknownTransactionID"

def extract_message_type(packet, protocol):
    # Determine if the message is a Request or Response based on protocol-specific fields
    if protocol == 'TCAP':
        # Map TCAP message type to Request/Response
        if hasattr(packet.tcap, 'begin_element'):
            return 'Request'
        elif hasattr(packet.tcap, 'end_element'):
            return 'Response'
        else:
            return 'Response'
    elif protocol == 'SS7-MAP':
        # Assuming SS7-MAP message type extraction
        if hasattr(packet.ss7map, 'msg_type'):
            return packet.ss7map.msg_type
    elif protocol == 'Diameter':
        # Diameter message type extraction (e.g., Request/Response Command Code)
        if hasattr(packet.diameter, 'command_code'):
            return "Request" if 'Request' in str(packet.diameter.command_code) else "Response"
    return "UnknownMessageType"

def calculate_response_times(transactions_df):
    # Group by transaction ID and calculate response time
    response_times = []
    for txn_id, group in transactions_df.groupby('transaction_id'):
        request = group[group['msg_type'] == 'Request']
        response = group[group['msg_type'] == 'Response']
        if not request.empty and not response.empty:
            response_time = response['timestamp'].iloc[0] - request['timestamp'].iloc[0]
            response_times.append({
                'transaction_id': txn_id,
                'protocol': group['protocol'].iloc[0],
                'response_time': response_time,
            })
    return pd.DataFrame(response_times)

def main(file_path):
    #global transactions

    #process_large_pcap(file_path)
    process = ProcessPCAP(file_path)
    process.workflow()

    # Parse the PCAP and extract transactions
    transactions = pd.DataFrame(process.transactions)
    if transactions.empty:
        print("No relevant packets found.")
        return

    print(transactions)

    # Calculate response times
    response_times = calculate_response_times(transactions)

    print(response_times)

    # Compute averages
    total_avg_response_time = response_times['response_time'].mean()
    avg_response_time_by_protocol = response_times.groupby('protocol')['response_time'].mean()

    print(f"Total Average Response Time: {total_avg_response_time}")
    print("Average Response Time by Protocol:")
    print(avg_response_time_by_protocol)

if __name__ == "__main__":
    pcap_file = "test.pcap"
    main(pcap_file)
