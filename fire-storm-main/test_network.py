import time
import unittest
from threading import Thread

from buffers import packets
from client import create_receiver, create_sender
from o import ps


class TestSolution(unittest.TestCase):
    data_received: dict[int, bytes] = {}

    def receive_msg(self, thread_id: int) -> None:
        receiver = create_receiver()

        try:
            while True:
                conn, _ = receiver.accept()
                conn_open = True
                while conn_open:
                    data = conn.recv(1024)

                    if len(data) == 0:
                        conn.close()
                        conn_open = False
                        break

                    if thread_id not in self.data_received:
                        self.data_received[thread_id] = b""
                    self.data_received[thread_id] += data

        except Exception:
            # print("Receiver thread - caught exception:", str(e))
            pass

        finally:
            receiver.close()

    def send_and_recv(self, packets: list[bytes], thread_count: int = 1):
        sender = create_sender()
        receiver_threads: list[Thread] = []

        for thread_id in range(thread_count):
            receiver_threads.append(Thread(target=self.receive_msg, args=(thread_id,)))
            receiver_threads[-1].start()

        time.sleep(1)
        for packet in packets:
            sender.sendall(packet)

        sender.close()

        for thread in receiver_threads:
            thread.join(timeout=5)

    def test_traffic(self):
        self.send_and_recv(packets.all)
        for i, packet in enumerate(packets.all):
            if i in packets.route1:
                self.assertIn(packet, self.data_received[0])
            if i in packets.route0:
                self.assertNotIn(packet, self.data_received[0])


if __name__ == "__main__":
    packets.all = ps(packets.all)
    print("Running test...")
    unittest.main()