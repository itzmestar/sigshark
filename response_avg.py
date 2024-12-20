import pyshark
import pandas as pd
from datetime import datetime
import multiprocessing as mp
import subprocess


class ProcessPCAP:
    def __init__(self, pcap_file: str, chunk_size: int = 10000, total_size: int = 2000000):
        self.pcap_file = pcap_file
        self.chunk_size = chunk_size
        self.total_size = total_size
        self.transactions = []
        self.transactions_df = None
        self.response_times_df = None
        self.total_packets = 0

    def find_num_of_packets(self):
        try:
            cmd = ['tshark', '-r', self.pcap_file, '-q', '-z', 'io,stat,0']
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            lines = result.stdout.splitlines()
            self.total_packets = int(lines[-2].split('|')[2].strip())
            print(f"Total packets: {self.total_packets}")
        except Exception as e:
            print(e)

    def split_pcap(self):
        processes = mp.cpu_count()

        packets_per_files = int(self.total_packets / processes)
        subprocesses = []
        for i in range(processes):
            try:
                output_file = f'__{i}___temp___.pcap'
                start = i * packets_per_files
                end = start + packets_per_files
                display_filter = f"frame.number >= {start} && frame.number < {end}"

                cmd = ['tshark', '-r', self.pcap_file, '-Y', display_filter, '-w', output_file]

                #subprocess.run(cmd, check=True)
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                subprocesses.append(process)
            except Exception as e:
                print(e)
        for process in subprocesses:
            process.wait()

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

    def process_chunk(self, start_index, chunk_size):
        capture = pyshark.FileCapture(self.pcap_file, keep_packets=False)
        transactions = []

        for i, packet in enumerate(capture):
            if i < start_index:
                continue
            if i >= start_index + chunk_size:
                break

            try:
                timestamp = float(packet.sniff_timestamp)

                if hasattr(packet, 'tcap'):
                    protocol = 'TCAP'
                    transaction_id = self.extract_transaction_id(packet, protocol)
                    msg_type = self.extract_message_type(packet, protocol)
                elif hasattr(packet, 'ss7map'):
                    protocol = 'SS7-MAP'
                    transaction_id = self.extract_transaction_id(packet, protocol)
                    msg_type = self.extract_message_type(packet, protocol)
                elif hasattr(packet, 'diameter'):
                    protocol = 'Diameter'
                    transaction_id = self.extract_transaction_id(packet, protocol)
                    msg_type = self.extract_message_type(packet, protocol)
                else:
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
        return transactions

    def generate_chunk_ranges(self):
        """
        Generator to yield start indices for chunks of packets.
        """
        start_index = 0
        while True:
            yield start_index, self.chunk_size
            start_index += self.chunk_size

    @staticmethod
    def process_chunk_helper(args):
        instance, chunk_start, chunk_end = args
        return instance.process_chunk(chunk_start, chunk_end)

    def process_pcap_parallel(self):
        processes = mp.cpu_count()
        print(f"Spawning {processes} processes...")
        chunk_ranges = [
            (self, start, start + self.chunk_size)
            for start in range(0, self.total_size, self.chunk_size)
        ]

        results = []
        with mp.Pool(processes=processes) as pool:
            for chunk_result in pool.imap_unordered(self.process_chunk_helper, chunk_ranges):
                if not chunk_result:  # Break the loop if no more packets are available
                    break
                results.append(chunk_result)

        self.transactions = [item for sublist in results for item in sublist]

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
        self.find_num_of_packets()
        self.split_pcap()
        #self.process_pcap_parallel()
        #self.convert_to_df()
        #self.calculate_response_times()
        #self.calculate_averages()


def main(file_path):
    print(datetime.now())
    process = ProcessPCAP(file_path)
    process.workflow()
    print(datetime.now())


if __name__ == "__main__":
    pcap_file = "test.pcap"
    main(pcap_file)
