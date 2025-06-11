# storage_server/abac.py
from charm.toolbox.policytree import PolicyParser

class ABAC:
    attr_dict = {
        'doctor': 1, 
        'patient': 2,
        'nurse': 3,
        'accountant': 4,
        'researcher': 5,
        'pharmacist': 6,
        'administrator': 7,
    }
    
    '''
    health_record_policy = "DOCTOR or PATIENT or NURSE"
    financial_policy = "ACCOUNTANT"
    research_report_policy = "DOCTOR or RESEARCHER"
    user_management_policy = "ADMINISTRATOR"
    '''
    
    def __init__(self):
        self.parser = PolicyParser()
    
    # Parse the policy and check if the attributes satisfy the policy
    def check(self, attributes: list, policy: str):
        tree = self.parser.parse(policy)
        check = self.parser.prune(tree, attributes)
        return check
    
    # Convert the policy and attributes to their corresponding integer values
    def convertPolicy(self, policy):
        for k in self.attr_dict:
            policy = policy.replace(k, self.attr_dict[k])
        return policy
    
    # Convert the attributes to their corresponding integer values
    def convertAttribute(self, attributes):
        converted_attr = []
        for a in attributes:
            for k in self.attr_dict:
                if a == k:
                    converted_attr.append(self.attr_dict[k]) 
        return converted_attr
    

def checker(user_attributes, policy_keywords):
    abac = ABAC()

    # Find user attributes that match any of the policy keywords
    matched_attributes = []
    for a in user_attributes:         
        for k in policy_keywords:   
            if k in a:          
                matched_attributes.append(a)

    # Prepare the final list of policy keywords to use in the policy string
    final_policy_keywords = policy_keywords.copy()
    for keyword in policy_keywords:
        for attr in matched_attributes:
            # Ensure each keyword is included only once
            if keyword in attr and keyword not in final_policy_keywords:
                final_policy_keywords.append(keyword)

    # Convert the policy keywords to their integer representation
    converted_policy = abac.convertPolicy(' or '.join(final_policy_keywords))
    # Convert the matched user attributes to their integer representation
    converted_attrs = abac.convertAttribute(matched_attributes)

    # Check if the converted attributes satisfy the converted policy
    return abac.check(converted_attrs, converted_policy)
