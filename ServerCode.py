import socket
import pickle
import pandas as pd
from sklearn.cross_decomposition import PLSCanonical
from sklearn.metrics import accuracy_score, classification_report,confusion_matrix
from sklearn.preprocessing import LabelEncoder
import time
import psutil
from memory_profiler import memory_usage
import socket
import pickle
import pandas as pd
import psutil
import matplotlib.pyplot as plt
from sklearn.cross_decomposition import PLSCanonical
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder
import time

# Matplotlib setup for live plotting
plt.ion()
fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(10, 8))
cpu_usage_data = []
memory_usage_data = []
batch_counter = []
batch_num = []
packet_counts = []

meanaccuracy=[]
meantime=[]
meanmeme=[]
meancpu=[]
# Load pre-trained models for feature extraction and classification
with open('feature_extractor.pkl', 'rb') as f:
    feature_extraction_model = pickle.load(f)
    
# Load pre-trained models for feature extraction and classification
with open('pls_canonical_model.pkl', 'rb') as f:
    psl_model = pickle.load(f)

with open('LogisticRegression.pkl', 'rb') as f:
    classification_model = pickle.load(f)

psl_model = PLSCanonical(n_components=15)

# Expected columns for Traditional and IoT datasets
expected_trad_columns = [
    'Protocol', 'Flow Duration', 'Fwd Packets Length Total', 'Bwd Packets Length Total',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std', 
    'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
    'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max', 'Bwd IAT Min', 
    'Fwd PSH Flags', 'Fwd Packets/s', 'Bwd Packets/s', 'Packet Length Min', 'Packet Length Max', 
    'Packet Length Mean', 'Packet Length Variance', 'RST Flag Count', 'ACK Flag Count',
    'URG Flag Count', 'CWE Flag Count', 'Down/Up Ratio', 'Avg Packet Size', 'Avg Fwd Segment Size', 
    'Avg Bwd Segment Size', 'Subflow Fwd Bytes', 'Subflow Bwd Bytes', 'Init Fwd Win Bytes', 
    'Init Bwd Win Bytes', 'Idle Mean', 'Idle Std', 'Idle Max'
]

expected_iot_columns = [
    'ts', 'id.orig_h', 'duration', 'orig_bytes', 'resp_bytes', 'orig_pkts',
    'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes', 'proto_icmp', 'proto_tcp',
    'proto_udp', 'conn_state_OTH', 'conn_state_REJ', 'conn_state_RSTO', 
    'conn_state_S0', 'conn_state_S3', 'conn_state_SF', 'conn_state_SH'
]

def apply_psl(iot_data, trad_data):
    iotdata=pd.DataFrame(iot_data,columns=expected_iot_columns)
    traddata=pd.DataFrame(trad_data,columns=expected_trad_columns)
    #print(traddata.shape)
    iot_aligned, trad_aligned = psl_model.fit_transform(iotdata, traddata)
    #print(iot_aligned.shape)
    combined_features = pd.concat([pd.DataFrame(iot_aligned), pd.DataFrame(trad_aligned)], ignore_index=True)
    return combined_features

def extract_features(data):
    features = feature_extraction_model.predict(data,verbose=0)
    return features

def classify(features):
    predictions = classification_model.predict(features)
    return predictions

def measure_cpu_usage_during_batch(batch_duration, interval=0.3):
    cpu_measurements = []
    start_time = time.time()
    
    while time.time() - start_time < batch_duration:
        # Measure CPU usage with a 0.3-second interval to match your batch frequency
        cpu_measurements.append(psutil.cpu_percent(interval=interval))
    
    # Calculate the average CPU usage over the batch period
    return sum(cpu_measurements) / len(cpu_measurements) if cpu_measurements else 0

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_socket.bind(('localhost', 8081))
server_socket.listen(1)
print("Server is listening on port 8081...")

while True:
    client_socket, address = server_socket.accept()
    print(f"Connection from {address} has been established.")

    try:
        data = b""
        while True:
            packet = client_socket.recv(4096)
            if not packet:
                print("Connection closed by client.")
                break
            data += packet
            if b"<END>" in data:
                data = data.replace(b"<END>", b"")
                break
        
        if data:  # Only process if data is received
            print("Batch received.")
            received_data = pickle.loads(data)
            #num_packets = len(received_data)  # Assuming received_data is a list of packets
            
            process = psutil.Process()
            initial_mem = process.memory_info().rss / 1024 ** 2  # in MB
            start_time = time.time()
            
            
            
            iot_features = received_data['iot_features']
            trad_features = received_data['trad_features']
            iot_target = received_data['iot_target']
            trad_target = received_data['trad_target']
            
            combined_features = apply_psl(iot_features, trad_features)
            extracted_features = extract_features(combined_features)
            predictions = classify(extracted_features)
            
            
            
            
            print("--- %s seconds ---" % (time.time() - start_time))
            meantime.append(time.time() - start_time)
            
            final_mem = process.memory_info().rss / 1024 ** 2  # in MB
            #final_cpu = process.cpu_percent(interval=0.02)
            Mem_use=final_mem - initial_mem
            #Cpu_use=final_cpu
            batch_duration = time.time() - start_time
            # Measure the average CPU usage over the batch duration
            Cpu_use = measure_cpu_usage_during_batch(batch_duration, interval=0.3)  # Adjust interval as needed
            final_cpu=Cpu_use




            combined_target = pd.concat([iot_target, trad_target], ignore_index=True)
            target = LabelEncoder().fit_transform(combined_target)
            
            accuracy = accuracy_score(target, predictions)
            meanaccuracy.append(accuracy)
            meanmeme.append(Mem_use)
            meancpu.append(Cpu_use)
            batch_counter.append(len(meanmeme))
            cpu_usage_data.append(Cpu_use)
            memory_usage_data.append(Mem_use)
            packet_counts.append(len(target))
            
            print("Packet recived",len(target))
            print(f"Batch accuracy: {accuracy * 100:.2f}%")
            print(f"Memory Usage (Approx): {Mem_use:.2f} MB")
            print(f"CPU Usage (Approx): {Cpu_use:.2f}%")
            
            #print(classification_report(target, predictions))
            #print(confusion_matrix(target, predictions))
            response = {'accuracy': accuracy, 'predictions': predictions}
            serialized_response = pickle.dumps(response) + b"<END>"
            client_socket.sendall(serialized_response)
            print("Predictions sent back to client.")
            
            # Plotting each metric
            ax1.cla()
            ax2.cla()
            ax3.cla()

            ax1.plot(batch_counter, cpu_usage_data, label='CPU Usage (%)', color='blue')
            ax2.plot(batch_counter, memory_usage_data, label='Memory Usage (MB)', color='green')
            ax3.plot(batch_counter, packet_counts, label='Packets Received', color='orange')

            ax1.set_ylabel("CPU Usage (%)")
            ax2.set_ylabel("Memory Usage (MB)")
            ax3.set_ylabel("Packets Received")
            ax3.set_xlabel("Batch Number")

            ax1.legend()
            ax2.legend()
            ax3.legend()

            # Autoscale for each subplot
            ax1.relim()
            ax2.relim()
            ax3.relim()
            ax1.autoscale_view()
            ax2.autoscale_view()
            ax3.autoscale_view()

            plt.pause(0.1)  # Brief pause to update pl
            
            

    except Exception as e:
        print(f"An error occurred: {e}")

    except KeyboardInterrupt:
        print("Mean Accuracy",sum(meanaccuracy)/len(meanaccuracy))
        print("Mean Time",sum(meantime)/len(meantime))
        print("Mean Memory",sum(meanmeme)/len(meanmeme))
        print("Mean CPU",sum(meancpu)/len(meancpu))
    
    finally:
        client_socket.close()
        print("Done")

plt.ioff()  # Disable interactive mode
plt.show()  # Keep the plot open after exiting the loop


