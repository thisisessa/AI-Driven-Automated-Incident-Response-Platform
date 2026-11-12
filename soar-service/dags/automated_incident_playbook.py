from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python import PythonOperator
import os
import sys

# Add Engine path to Python sys path
sys.path.append("/app")

from engine.decision_tree import DynamicDecisionEngine
from engine.thehive_cortex_integrator import IncidentIntegrator

default_args = {
    'owner': 'EduQual_DevSecOps',
    'depends_on_past': False,
    'start_date': datetime(2026, 1, 1),
    'email_on_failure': False,
    'retries': 1,
    'retry_delay': timedelta(minutes=1),
}

dag = DAG(
    'SOAR_Automated_Playbook_Workflow',
    default_args=default_args,
    description='Orchestrates Threat Evaluation, Cortex Checks, and TheHive Case Creation',
    schedule_interval=timedelta(seconds=30),  # Polls every 30 seconds
    catchup=False
)

def poll_and_evaluate_alerts(**kwargs):
    """
    Step 1: Poll active threat logs and pass to Decision Tree.
    """
    sample_alert = {
        "attack_type": "Ransomware_Execution_Attempt",
        "source_ip": "185.220.101.5",
        "misp_ioc_match": True,
        "failed_attempts": 14
    }

    engine = DynamicDecisionEngine()
    decision = engine.evaluate_threat_context(sample_alert)

    kwargs['ti'].xcom_push(key='alert_data', value=sample_alert)
    kwargs['ti'].xcom_push(key='decision_meta', value=decision)

def execute_incident_response(**kwargs):
    """
    Step 2: Streamlined Incident Response handling Case creation, 
            Observable addition, and Cortex Job Execution in one flow.
    """
    ti = kwargs['ti']
    alert_data = ti.xcom_pull(key='alert_data', task_ids='poll_and_evaluate')
    decision_meta = ti.xcom_pull(key='decision_meta', task_ids='poll_and_evaluate')

    integrator = IncidentIntegrator()
    response_res = integrator.create_thehive_case(alert_data, decision_meta)
    print(f"Automated SOAR Pipeline Executed Successfully. Results: {response_res}")
    ti.xcom_push(key='response_result', value=response_res)

# Define DAG Tasks
t1 = PythonOperator(
    task_id='poll_and_evaluate',
    python_callable=poll_and_evaluate_alerts,
    provide_context=True,
    dag=dag,
)

t2 = PythonOperator(
    task_id='execute_incident_response',
    python_callable=execute_incident_response,
    provide_context=True,
    dag=dag,
)

# Set Sequential Dependency Pipeline
t1 >> t2
