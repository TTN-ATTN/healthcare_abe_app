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
        'neurology_doctor': 8,
        'virus_researcher': 9,
        'executive_accountant': 10,
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
    def check(self, attribute: list, policy: str):
        tree = self.parser.parse(policy)
        check = self.parser.prune(tree, attribute)
        return check
    
    # Convert the policy and attributes to their corresponding integer values
    def convertPolicy(self, policy):
        for k in self.attr_dict:
            policy = policy.replace(k, self.attr_dict[k])
        return policy
    
    # Convert the attributes to their corresponding integer values
    def convertAttribute(self, attribute):
        converted_attr = []
        for a in attribute:
            for k in self.attr_dict:
                if a == k:
                    converted_attr.append(self.attr_dict[k]) 
        return converted_attr
    

def checker(user_attributes, policy_keywords):
    abac = ABAC()

    matched_attributes = []
    for a in user_attributes:         
        for k in policy_keywords:   
            if k in a:          
                matched_attributes.append(a)

    final_policy_keywords = policy_keywords.copy()
    for keyword in policy_keywords:
        for attr in matched_attributes:
            if keyword in attr and keyword not in final_policy_keywords:
                final_policy_keywords.append(keyword)

    converted_policy = abac.convertPolicy(' or '.join(final_policy_keywords))
    converted_attrs = abac.convertAttribute(matched_attributes)

    return abac.check(converted_attrs, converted_policy)
