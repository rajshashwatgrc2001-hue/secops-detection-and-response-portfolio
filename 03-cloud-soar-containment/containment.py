import boto3
import json
from botocore.exceptions import ClientError

def revoke_iam_user_sessions(username: str):
    """Attaches an explicit Deny-All inline policy to immediately invalidate active IAM sessions."""
    iam = boto3.client('iam')
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*"
            }
        ]
    }
    try:
        iam.put_user_policy(
            UserName=username,
            PolicyName='EmergencyContainmentDenyAll',
            PolicyDocument=json.dumps(policy_document)
        )
        print(f"[CONTAINMENT] Successfully attached Deny-All policy to {username}")
        return True
    except ClientError as e:
        print(f"[ERROR] Failed to revoke sessions for {username}: {e}")
        return False

def isolate_ec2_instance(instance_id: str, isolation_sg_id: str):
    """Replaces current security groups with an empty quarantine security group."""
    ec2 = boto3.client('ec2')
    try:
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[isolation_sg_id]
        )
        print(f"[CONTAINMENT] Instance {instance_id} network isolated via SG: {isolation_sg_id}")
        return True
    except ClientError as e:
        print(f"[ERROR] Failed to isolate instance {instance_id}: {e}")
        return False

if __name__ == "__main__":
    sample_alert = {
        "compromised_user": "compromised-service-account",
        "affected_ec2": "i-0abcd1234ef567890",
        "quarantine_sg": "sg-0987654321quarantine"
    }
    print("Initiating automated SOAR containment pipeline...")
    revoke_iam_user_sessions(sample_alert["compromised_user"])
    isolate_ec2_instance(sample_alert["affected_ec2"], sample_alert["quarantine_sg"])
