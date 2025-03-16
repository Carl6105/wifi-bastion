from pymongo import MongoClient
from config import MONGO_URI, MONGO_DB, MONGO_COLLECTION
import logging
import time

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DatabaseManager:
    """Handles all database operations for the Wi-Fi Bastion application."""
    
    def __init__(self):
        """Initialize database connection using configuration settings."""
        try:
            self.client = MongoClient(MONGO_URI)
            self.db = self.client[MONGO_DB]
            self.collection = self.db[MONGO_COLLECTION]
            logger.info(f"Connected to MongoDB database: {MONGO_DB}")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {str(e)}")
            raise
    
    def insert_networks(self, networks):
        """Insert new networks into the database.
        
        Args:
            networks (list): List of network dictionaries to insert
            
        Returns:
            tuple: (success, result_or_error) where success is a boolean and
                  result_or_error is either the inserted IDs or an error message
        """
        try:
            if not networks:
                return True, []
                
            result = self.collection.insert_many(networks)
            logger.info(f"Inserted {len(result.inserted_ids)} networks into database")
            return True, result.inserted_ids
        except Exception as e:
            logger.error(f"Error inserting networks into database: {str(e)}")
            return False, str(e)
    
    def find_existing_networks(self, ssids):
        """Find existing networks in the database by their SSIDs.
        
        Args:
            ssids (list): List of SSIDs to search for
            
        Returns:
            dict: Dictionary mapping SSIDs to their database documents
        """
        try:
            if not ssids:
                return {}
                
            existing_networks = self.collection.find({"ssid": {"$in": ssids}})
            return {doc['ssid']: doc for doc in existing_networks}
        except Exception as e:
            logger.error(f"Error finding existing networks: {str(e)}")
            return {}
    
    def get_all_scans(self):
        """Retrieve all network scans from the database.
        
        Returns:
            tuple: (success, result_or_error) where success is a boolean and
                  result_or_error is either the scan results or an error message
        """
        try:
            scans = list(self.collection.find())
            return True, scans
        except Exception as e:
            logger.error(f"Error fetching scan history: {str(e)}")
            return False, str(e)
            
    def block_network(self, network_id, bssid):
        """Add a network to the blocklist.
        
        Args:
            network_id (str): The ID of the network to block
            bssid (str): The BSSID of the network to block
            
        Returns:
            tuple: (success, result_or_error) where success is a boolean and
                  result_or_error is either the success message or an error message
        """
        try:
            # Create a blocklist collection if it doesn't exist
            if 'blocklist' not in self.db.list_collection_names():
                self.db.create_collection('blocklist')
                
            # Check if network is already blocked
            if self.db.blocklist.find_one({"bssid": bssid}):
                return True, "Network already blocked"
                
            # Add network to blocklist
            result = self.db.blocklist.insert_one({
                "network_id": network_id,
                "bssid": bssid,
                "blocked_at": time.time()
            })
            
            logger.info(f"Blocked network with BSSID {bssid}")
            return True, "Network successfully blocked"
        except Exception as e:
            logger.error(f"Error blocking network: {str(e)}")
            return False, str(e)
    
    def get_blocked_networks(self):
        """Get all blocked networks.
        
        Returns:
            tuple: (success, result_or_error) where success is a boolean and
                  result_or_error is either the list of blocked networks or an error message
        """
        try:
            if 'blocklist' not in self.db.list_collection_names():
                return True, []
                
            blocked = list(self.db.blocklist.find())
            # Convert ObjectId to string for each document
            for network in blocked:
                network["_id"] = str(network["_id"])
            
            return True, blocked
        except Exception as e:
            logger.error(f"Error getting blocked networks: {str(e)}")
            return False, str(e)
            
    def unblock_network(self, network_id):
        """Remove a network from the blocklist.
        
        Args:
            network_id (str): The ID of the network to unblock
            
        Returns:
            tuple: (success, result_or_error) where success is a boolean and
                  result_or_error is either the success message or an error message
        """
        try:
            if 'blocklist' not in self.db.list_collection_names():
                return False, "Blocklist collection does not exist"
                
            # Delete the network from blocklist
            from bson.objectid import ObjectId
            result = self.db.blocklist.delete_one({"_id": ObjectId(network_id)})
            
            if result.deleted_count == 0:
                return False, "Network not found in blocklist"
                
            logger.info(f"Unblocked network with ID {network_id}")
            return True, "Network successfully unblocked"
        except Exception as e:
            logger.error(f"Error unblocking network: {str(e)}")
            return False, str(e)
