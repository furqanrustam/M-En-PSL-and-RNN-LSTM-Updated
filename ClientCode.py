import socket
import pickle
import pandas as pd
import numpy as np

# Load IoT and Traditional data
iot_data = pd.read_csv('IotData.csv')
trad_data = pd.read_csv('tradData.csv')

target_column = 'Target'
iot_features = iot_data.drop(columns=[target_column])
iot_target = iot_data[target_column]
trad_features = trad_data.drop(columns=[target_column,'Label'])
trad_target = trad_data[target_column]



def send_batch(iot_batch, trad_batch, iot_target_batch, trad_target_batch):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(('localhost', 8081))

        data = {
            'iot_features': iot_batch,
            'trad_features': trad_batch,
            'iot_target': iot_target_batch,
            'trad_target': trad_target_batch
        }
        serialized_data = pickle.dumps(data) + b"<END>"

        # Send data to the server
        client_socket.sendall(serialized_data)
        print("Batch sent to the server.")

        # Receive the response from the server
        response = b""
        while True:
            packet = client_socket.recv(4096)
            if not packet:
                break
            response += packet
            if b"<END>" in response:
                response = response.replace(b"<END>", b"")  # Remove the delimiter
                break

        # Deserialize response
        response_data = pickle.loads(response)
        accuracy = response_data['accuracy']
        print(f"Received accuracy: {accuracy * 100:.2f}%")

while True:
    num=np.random.randint(200, 600)
    iot_batch_size = num
    trad_batch_size = num
    iot_indices = iot_features.sample(n=iot_batch_size).index
    trad_indices = trad_features.sample(n=trad_batch_size).index

    iot_batch = iot_features.loc[iot_indices]
    iot_target_batch = iot_target.loc[iot_indices]
    trad_batch = trad_features.loc[trad_indices]
    trad_target_batch = trad_target.loc[trad_indices]

    send_batch(iot_batch, trad_batch, iot_target_batch, trad_target_batch)

