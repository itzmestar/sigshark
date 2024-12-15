import pyshark
import pandas as pd
from datetime import datetime


class ProcessPCAP:
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.capture = pyshark.FileCapture(pcap_file, keep_packets=False)
        print("PCAP file loaded.")
        self.transactions = []
        self.transactions_df = None
        self.response_times_df = None

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
            if i == 10000:
                break
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

    def convert_to_df(self):
        self.transactions_df = pd.DataFrame(self.transactions)

    def calculate_response_times(self):
        # Group by transaction ID and calculate response time
        response_times = []
        for txn_id, group in self.transactions_df.groupby('transaction_id'):
            request = group[group['msg_type'] == 'Request']
            response = group[group['msg_type'] == 'Response']
            if not request.empty and not response.empty:
                response_time = response['timestamp'].iloc[0] - request['timestamp'].iloc[0]
                response_times.append({
                    'transaction_id': txn_id,
                    'protocol': group['protocol'].iloc[0],
                    'response_time': response_time,
                })
        self.response_times_df = pd.DataFrame(response_times)

    def calculate_averages(self):
        # Compute averages
        total_avg_response_time = self.response_times_df['response_time'].mean()
        avg_response_time_by_protocol = self.response_times_df.groupby('protocol')['response_time'].mean()

        print(f"Total Average Response Time: {total_avg_response_time}")
        print("Average Response Time by Protocol:")
        print(avg_response_time_by_protocol)

    def workflow(self):
        self.process_pcap()
        self.convert_to_df()
        self.calculate_response_times()
        self.calculate_averages()


def main(file_path):
    print(datetime.now())
    process = ProcessPCAP(file_path)
    process.workflow()
    print(datetime.now())


if __name__ == "__main__":
    pcap_file = "test.pcap"
    main(pcap_file)
