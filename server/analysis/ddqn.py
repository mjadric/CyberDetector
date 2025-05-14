"""
Double Deep Q-Network (DDQN) implementation for DDoS attack detection and mitigation.
Based on methodology described in the uploaded document.
"""

import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.losses import MSE
import random
from collections import deque
import os

# Enable GPU memory growth to prevent TensorFlow from allocating all GPU memory
physical_devices = tf.config.list_physical_devices('GPU')
if physical_devices:
    try:
        for device in physical_devices:
            tf.config.experimental.set_memory_growth(device, True)
    except Exception:
        print("Memory growth setting not supported")

class DDQNAgent:
    """
    Double Deep Q-Network (DDQN) agent for DDoS detection and mitigation
    
    Attributes:
        state_size (int): Size of the state vector
        action_size (int): Number of available actions
        memory (deque): Replay memory to store experiences
        gamma (float): Discount factor for future rewards
        epsilon (float): Exploration rate
        epsilon_min (float): Minimum exploration rate
        epsilon_decay (float): Decay rate for exploration
        learning_rate (float): Learning rate for the optimizer
        update_rate (int): How often to update the target network
        policy_model (Sequential): Neural network for action selection
        target_model (Sequential): Target network for stable learning
        feature_weights (np.array): Weights for the features based on OneR algorithm
    """
    
    def __init__(
        self,
        state_size=8,
        action_size=4,
        memory_size=10000,
        gamma=0.95,
        epsilon=1.0,
        epsilon_min=0.01,
        epsilon_decay=0.995,
        learning_rate=0.001,
        update_rate=100
    ):
        self.state_size = state_size
        self.action_size = action_size
        self.memory = deque(maxlen=memory_size)
        self.gamma = gamma  # discount factor
        self.epsilon = epsilon  # exploration rate
        self.epsilon_min = epsilon_min
        self.epsilon_decay = epsilon_decay
        self.learning_rate = learning_rate
        self.update_rate = update_rate
        self.step_counter = 0
        
        # Feature weights based on OneR algorithm for DDoS detection 
        # as specified in the methodology document
        self.feature_weights = np.array([
            0.18,  # source_entropy
            0.12,  # destination_entropy
            0.25,  # syn_ratio
            0.15,  # traffic_volume
            0.20,  # packet_rate
            0.05,  # unique_src_ips_count
            0.02,  # unique_dst_ips_count
            0.03   # protocol_distribution
        ])
        
        # Initialize models
        self.policy_model = self._build_model()
        self.target_model = self._build_model()
        self.update_target_model()
    
    def _build_model(self):
        """
        Build a neural network model for the agent
        
        Returns:
            Sequential: Keras Sequential model
        """
        model = Sequential([
            Dense(64, input_dim=self.state_size, activation='relu'),
            Dense(64, activation='relu'),
            Dense(32, activation='relu'),
            Dense(self.action_size, activation='linear')
        ])
        model.compile(loss='mse', optimizer=Adam(learning_rate=self.learning_rate))
        return model
    
    def update_target_model(self):
        """Update the target model with weights from policy model"""
        self.target_model.set_weights(self.policy_model.get_weights())
    
    def process_state(self, state):
        """
        Apply feature weighting to the state vector
        
        Args:
            state (np.array): The raw state vector
            
        Returns:
            np.array: Weighted state vector
        """
        return state * self.feature_weights
    
    def remember(self, state, action, reward, next_state, done):
        """
        Store experience in replay memory
        
        Args:
            state (np.array): Current state
            action (int): Action taken
            reward (float): Reward received
            next_state (np.array): Next state
            done (bool): Whether the episode is done
        """
        # Apply feature weighting to states
        weighted_state = self.process_state(state)
        weighted_next_state = self.process_state(next_state)
        
        self.memory.append((weighted_state, action, reward, weighted_next_state, done))
    
    def act(self, state):
        """
        Choose an action based on the current state (epsilon-greedy policy)
        
        Args:
            state (np.array): Current state
            
        Returns:
            int: Selected action
        """
        weighted_state = self.process_state(state)
        
        if np.random.rand() <= self.epsilon:
            return random.randrange(self.action_size)
        
        act_values = self.policy_model.predict(np.array([weighted_state]), verbose=0)
        return np.argmax(act_values[0])
    
    def replay(self, batch_size):
        """
        Train the agent with experiences from memory
        
        Args:
            batch_size (int): Number of experiences to sample
            
        Returns:
            float: Loss value from training
        """
        if len(self.memory) < batch_size:
            return 0
        
        minibatch = random.sample(self.memory, batch_size)
        losses = []
        
        for state, action, reward, next_state, done in minibatch:
            target = reward
            
            if not done:
                # DDQN: Select action using policy network
                a = np.argmax(self.policy_model.predict(np.array([next_state]), verbose=0)[0])
                # But evaluate its value using the target network
                target = reward + self.gamma * self.target_model.predict(np.array([next_state]), verbose=0)[0][a]
            
            target_f = self.policy_model.predict(np.array([state]), verbose=0)
            target_f[0][action] = target
            
            history = self.policy_model.fit(np.array([state]), target_f, epochs=1, verbose=0)
            losses.append(history.history['loss'][0])
        
        # Decay epsilon
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
        
        # Periodically update target network
        self.step_counter += 1
        if self.step_counter % self.update_rate == 0:
            self.update_target_model()
            
        return np.mean(losses)
    
    def load(self, name):
        """
        Load model weights from file
        
        Args:
            name (str): File path
        """
        try:
            self.policy_model.load_weights(name)
            self.update_target_model()
            print(f"Successfully loaded weights from {name}")
        except Exception as e:
            print(f"Failed to load weights: {e}")
    
    def save(self, name):
        """
        Save model weights to file
        
        Args:
            name (str): File path
        """
        try:
            self.policy_model.save_weights(name)
            print(f"Successfully saved weights to {name}")
        except Exception as e:
            print(f"Failed to save weights: {e}")

def create_mitigation_action(action_index, intensity=None):
    """
    Convert action index to human-readable mitigation action
    
    Args:
        action_index (int): Index of the action
        intensity (float, optional): Intensity parameter for the action
        
    Returns:
        dict: Mitigation action details
    """
    actions = {
        0: {"name": "Monitor", "description": "Continue monitoring without taking action"},
        1: {"name": "Rate Limit", "description": "Apply rate limiting to suspicious traffic"},
        2: {"name": "Block IP", "description": "Block specific source IPs identified as attackers"},
        3: {"name": "Filter", "description": "Apply packet filtering based on signature"}
    }
    
    action = actions.get(action_index, {"name": "Unknown", "description": "Unknown action"})
    
    if intensity is not None:
        action["intensity"] = intensity
        
    return action

def normalize_state(state):
    """
    Normalize state values to the range [0,1]
    
    Args:
        state (list): Raw state values
        
    Returns:
        np.array: Normalized state values
    """
    # Shannon entropy is already between 0 and 1
    # SYN ratio is already between 0 and 1
    # Normalize traffic volume (assuming max value of 10000 packets/s)
    state[3] = min(state[3] / 10000.0, 1.0)
    # Normalize packet rate (assuming max value of 10000 packets/s)
    state[4] = min(state[4] / 10000.0, 1.0)
    # Normalize unique IP counts (assuming max values of 1000)
    state[5] = min(state[5] / 1000.0, 1.0)
    state[6] = min(state[6] / 1000.0, 1.0)
    # Protocol distribution imbalance is already between 0 and 1
    
    return np.array(state)

def get_reward(state, action, next_state, is_attack=False):
    """
    Calculate reward for the agent based on state, action and ground truth
    
    Args:
        state (np.array): Current state
        action (int): Taken action
        next_state (np.array): Next state
        is_attack (bool): Ground truth of whether this is an attack
        
    Returns:
        float: Reward value
    """
    syn_ratio = state[2]
    traffic_volume = state[3] * 10000  # Denormalize
    source_entropy = state[0]
    
    # Detecting and mitigating real attacks should be highly rewarded
    if is_attack:
        if action == 0:  # Just monitoring during an attack
            return -10.0
        elif action == 1:  # Rate limiting during attack (good response)
            return 5.0
        elif action == 2:  # Blocking IPs during attack (best response for most attacks)
            return 10.0
        elif action == 3:  # Filtering (good for some attacks)
            return 7.0
    else:
        # False positives should be penalized
        if action == 0:  # Correctly monitoring normal traffic
            return 1.0
        else:  # Taking action on normal traffic (false positive)
            return -5.0
    
    return 0.0

if __name__ == "__main__":
    # Example usage
    state_size = 8
    action_size = 4
    agent = DDQNAgent(state_size=state_size, action_size=action_size)
    
    # Check if saved model exists and load it
    model_path = os.path.join(os.path.dirname(__file__), "ddqn_weights.h5")
    if os.path.exists(model_path):
        agent.load(model_path)
    
    print("DDQN agent initialized successfully.")
