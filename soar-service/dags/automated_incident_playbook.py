from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python import PythonOperator
import os
import sys

sys.path.append("/app")

from engine.decision_tree import DynamicDecisionEngine
from engine.thehive_cortex_integrator import IncidentIntegrator
from engine.action_executor import ActionExecutor

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
    description='Orchestrates Threat Simulation → Decision → Case → Response',
    schedule_interval=timedelta(minutes=10),  # <--- HAR 10 MINUTE MEIN AUTO RUN HOGA
    catchup=False
)

def generate_threat(**kwargs):
    """Step 1: Generate threat (simulated)"""
    from threat_simulator import ThreatSimulator
    sim = ThreatSimulator()
    alert_data = sim.generate_threat_payload()
    print(f"[AIRFLOW] Generated threat: {alert_data['attack_type']} from {alert_data['source_ip']}")
    kwargs['ti'].xcom_push(key='alert_data', value=alert_data)
    return alert_data['alert_id']

def poll_and_evaluate(**kwargs):
    """Step 2: AI Decision Engine (ML + MISP + TensorFlow)"""
    ti = kwargs['ti']
    alert_data = ti.xcom_pull(key='alert_data', task_ids='generate_threat')
    engine = DynamicDecisionEngine()
    decision = engine.evaluate_threat_context(alert_data)
    print(f"[AIRFLOW] Decision: Score={decision['calculated_score']} | Playbook={decision['playbook']}")
    ti.xcom_push(key='decision_meta', value=decision)
    return decision['playbook']

def execute_incident_response(**kwargs):
    """Step 3: TheHive + Cortex + Action Execution"""
    ti = kwargs['ti']
    alert_data = ti.xcom_pull(key='alert_data', task_ids='generate_threat')
    decision_meta = ti.xcom_pull(key='decision_meta', task_ids='poll_and_evaluate')

    integrator = IncidentIntegrator()
    response_res = integrator.create_thehive_case(alert_data, decision_meta)

    executor = ActionExecutor()
    action_res = executor.execute_playbook_action(decision_meta, alert_data)

    print(f"[AIRFLOW] Response executed: {response_res}")
    print(f"[AIRFLOW] Actions: {action_res}")
    ti.xcom_push(key='response_result', value=response_res)
    return "SUCCESS"

# DAG Tasks
t1 = PythonOperator(task_id='generate_threat', python_callable=generate_threat, provide_context=True, dag=dag)
t2 = PythonOperator(task_id='poll_and_evaluate', python_callable=poll_and_evaluate, provide_context=True, dag=dag)
t3 = PythonOperator(task_id='execute_incident_response', python_callable=execute_incident_response, provide_context=True, dag=dag)

t1 >> t2 >> t3
