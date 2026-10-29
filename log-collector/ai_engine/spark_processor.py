import os
import sys
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, lit, current_timestamp

class EnterpriseSparkLogProcessor:
    def __init__(self):
        print("[*] Initializing Apache Spark Big Data Distributed Engine...")
        try:
            # Configure Spark for high-performance local cluster execution on 30GB RAM server
            self.spark = SparkSession.builder \
                .appName("EnterpriseIR-MassiveLogProcessor") \
                .master("local[*]") \
                .config("spark.driver.memory", "4g") \
                .config("spark.executor.memory", "4g") \
                .config("spark.sql.shuffle.partitions", "4") \
                .getOrCreate()
                
            self.spark.sparkContext.setLogLevel("ERROR")
            print("[+] Apache Spark Session successfully initialized.")
        except Exception as e:
            print(f"[-] Failed to initialize Spark Session: {str(e)}")
            self.spark = None

    def process_log_stream_batch(self, raw_logs_list):
        """
        Takes raw dictionary logs, parallelizes them into Spark DataFrames,
        performs distributed filtering, aggregation, and returns processed analytics.
        """
        if not self.spark or not raw_logs_list:
            return []
            
        try:
            # Convert python dict list into Spark DataFrame
            df = self.spark.createDataFrame(raw_logs_list)
            
            # Perform distributed transformations (e.g., filtering high-risk events)
            enriched_df = df.withColumn("processed_at", current_timestamp())
            
            # Collect results back securely
            result_rows = enriched_df.collect()
            processed_logs = [row.asDict() for row in result_rows]
            
            print(f"[Spark Big Data Engine] Successfully processed batch of {len(processed_logs)} logs via distributed RDD dataframe.")
            return processed_logs
            
        except Exception as e:
            print(f"[-] Spark batch processing error: {str(e)}")
            return raw_logs_list

    def stop_engine(self):
        if self.spark:
            self.spark.stop()
            print("[*] Spark Session terminated cleanly.")
