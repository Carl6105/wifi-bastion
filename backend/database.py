from pymongo import MongoClient
from bson.objectid import ObjectId
from pymongo.errors import ServerSelectionTimeoutError
import logging
import subprocess
import platform
import datetime
import time

try:
    from backend.config import MONGO_URI, MONGO_DB, MONGO_COLLECTION
except ImportError:
    from config import MONGO_URI, MONGO_DB, MONGO_COLLECTION

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DatabaseManager:
    def __init__(self):
        try:
            # 2-second timeout to catch connection issues immediately
            self.client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=2000)
            self.db = self.client[MONGO_DB]
            self.collection = self.db[MONGO_COLLECTION]
            
            # This triggers an actual connection attempt
            self.client.server_info() 
            logger.info(f"Successfully connected to MongoDB: {MONGO_DB}")
        except ServerSelectionTimeoutError:
            logger.error("Failed to connect to MongoDB. Is the service started?")
            raise
        except Exception as e:
            logger.error(f"Database error: {str(e)}")
            raise
    
    def insert_networks(self, networks):
        try:
            if not networks:
                return True, []
            result = self.collection.insert_many(networks)
            return True, [str(id) for id in result.inserted_ids]
        except Exception as e:
            return False, str(e)
    
    def find_existing_networks(self, ssids):
        try:
            if not ssids:
                return {}
            existing = self.collection.find({"ssid": {"$in": ssids}})
            return {doc['ssid']: {**doc, '_id': str(doc['_id'])} for doc in existing}
        except Exception as e:
            return {}
    
    def get_all_scans(self):
        try:
            # Sort by timestamp newest first
            scans = list(self.collection.find().sort("timestamp", -1))
            for scan in scans:
                scan["_id"] = str(scan["_id"])
            return True, scans
        except Exception as e:
            return False, str(e)

    def clear_all_scans(self):
        """Removes all documents from the scans collection."""
        try:
            result = self.collection.delete_many({})
            logger.info(f"Cleared {result.deleted_count} records from scan history.")
            return True, "History successfully cleared."
        except Exception as e:
            return False, str(e)

    def block_network(self, network_id, bssid, ssid):
        """
        Blocks a network in the database and applies an OS-level filter.
        """
        try:
            # 1. Update Database Status in main collection
            self.collection.update_one(
                {"_id": ObjectId(network_id)},
                {"$set": {"is_blocked": True}}
            )
            
            # 2. Add to dedicated Blocklist Collection
            if not self.db.blocklist.find_one({"bssid": bssid}):
                self.db.blocklist.insert_one({
                    "network_id": network_id,
                    "bssid": bssid,
                    "ssid": ssid,
                    "timestamp": datetime.datetime.now()
                })

            # 3. OS-LEVEL BLOCKING (Windows specific)
            if platform.system() == "Windows" and ssid:
                # This command prevents Windows from seeing or connecting to this SSID
                cmd = f'netsh wlan add filter permission=block ssid="{ssid}" networktype=infrastructure'
                subprocess.run(cmd, shell=True, check=True)
                logger.info(f"OS-level block applied to SSID: {ssid}")

            return True, "Network blocked successfully"
        except Exception as e:
            logger.error(f"Blocking failed: {e}")
            return False, str(e)

    def get_blocked_networks(self):
        """Returns all networks currently in the blocklist."""
        try:
            blocked = list(self.db.blocklist.find())
            for network in blocked:
                network["_id"] = str(network["_id"])
            return True, blocked
        except Exception as e:
            return False, str(e)

    def unblock_network(self, block_id, ssid=None):
        """
        Removes the OS-level filter and removes record from blocklist.
        """
        try:
            # 1. Remove from blocklist collection
            result = self.db.blocklist.delete_one({"_id": ObjectId(block_id)})
            
            # 2. OS-LEVEL UNBLOCKING (Windows)
            if platform.system() == "Windows" and ssid:
                cmd = f'netsh wlan delete filter permission=block ssid="{ssid}" networktype=infrastructure'
                subprocess.run(cmd, shell=True, check=True)
                logger.info(f"OS-level block removed for SSID: {ssid}")
                
            if result.deleted_count == 0:
                return False, "Network not found in blocklist"
                
            return True, "Network unblocked successfully"
        except Exception as e:
            logger.error(f"Unblocking failed: {e}")
            return False, str(e)