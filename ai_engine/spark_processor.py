import os
import sys
import json
import logging
from pyspark.sql import SparkSession
from pyspark.sql.functions import col, current_timestamp, count, avg, sum as spark_sum

logger = logging.getLogger("SOAR-Spark")

class EnterpriseSparkLogProcessor:
    def __init__(self):
        logger.info("[SPARK] Initializing Apache Spark Big Data Distributed Engine...")
        try:
            self.spark = SparkSession.builder \
                .appName("EnterpriseIR-MassiveLogProcessor") \
                .master("local[*]") \
                .config("spark.driver.memory", "2g") \
                .config("spark.executor.memory", "2g") \
                .config("spark.sql.shuffle.partitions", "4") \
                .config("spark.ui.port", "4040") \
                .getOrCreate()

            self.spark.sparkContext.setLogLevel("ERROR")
            logger.info(f"[SPARK] Spark Session initialized. Version: {self.spark.version}")
            logger.info(f"[SPARK] Spark UI available at: {self.spark.sparkContext.uiWebUrl}")
        except Exception as e:
            logger.error(f"[SPARK] Failed to initialize: {str(e)}")
            self.spark = None

    def _create_df_safely(self, raw_logs_list):
        """
        Helper method to safely convert logs to Spark DataFrame using JSON strings.
        This prevents 'CANNOT_DETERMINE_TYPE' errors when logs have mixed/missing data types.
        """
        # Convert dictionaries to JSON strings
        json_strings = [json.dumps(row) for row in raw_logs_list]
        # Parallelize into Spark RDD
        rdd = self.spark.sparkContext.parallelize(json_strings)
        # Read as JSON DataFrame
        return self.spark.read.json(rdd)

    def process_log_stream_batch(self, raw_logs_list):
        if not self.spark or not raw_logs_list:
            return []

        try:
            # Use the safe JSON method instead of createDataFrame
            df = self._create_df_safely(raw_logs_list)
            enriched_df = df.withColumn("processed_at", current_timestamp())
            result_rows = enriched_df.collect()
            processed_logs = [row.asDict() for row in result_rows]
            logger.info(f"[SPARK] Processed batch of {len(processed_logs)} logs via distributed DataFrame.")
            return processed_logs
        except Exception as e:
            logger.error(f"[SPARK] Batch processing error: {str(e)}")
            return raw_logs_list

    def aggregate_alerts(self, raw_logs_list):
        """
        GAP 7 FIX: Multi-source event correlation and intelligent alert aggregation
        """
        if not self.spark or not raw_logs_list:
            return []

        try:
            # Use the safe JSON method here too
            df = self._create_df_safely(raw_logs_list)

            # Aggregation: same IP + same event_type ko group karo
            agg_df = df.groupBy("source_ip", "event_type").agg(
                count("*").alias("event_count"),
                avg("ai_risk_score").alias("avg_risk_score"),
                spark_sum("volume").alias("total_volume")
            ).filter(col("event_count") >= 1)

            results = agg_df.collect()
            logger.info(f"[SPARK AGGREGATION] Correlated {len(results)} alert groups")
            for row in results:
                logger.info(
                    f"[SPARK AGGREGATION] IP={row['source_ip']} | Type={row['event_type']} | "
                    f"Count={row['event_count']} | AvgRisk={row['avg_risk_score']:.1f} | "
                    f"TotalVolume={row['total_volume']}"
                )
            return [r.asDict() for r in results]
        except Exception as e:
            logger.error(f"[SPARK] Aggregation error: {str(e)}")
            return []

    def stop_engine(self):
        if self.spark:
            self.spark.stop()
            logger.info("[SPARK] Session terminated cleanly.")
