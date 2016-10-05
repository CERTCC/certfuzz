'''
Created on Oct 24, 2012

@organization: cert.org
'''

def check_for_apis(module, api_list):
    missing_apis = []
    for api in api_list:
        if not hasattr(module, api):
            missing_apis.append((module.__name__, api))
    fail_lines = ['API missing: %s.%s not found' % ma for ma in missing_apis]
    fail_string = '\n'.join(fail_lines)
    return (bool(len(missing_apis)), fail_string)
