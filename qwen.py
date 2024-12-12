#!/usr/bin/env python
# coding: utf-8

# In[ ]:


rewrite the impact statement which is provided in the input according to the guideline mentioned in the impct_g section of the guildelines pdf provided.


# In[1]:


sample_data = {  
  "sample_issues": [  
    "Periodic Access Review – (COC/COI) Management’s existing recertification and termination controls for COC/COI do not consistently detect terminated employees.",  
    "Periodic Access Review - External Users (TCP) The periodic access review for users of TCP at the Treatment Centers (external to J&J) does not currently require independent confirmation of appropriateness of access.",  
    "Periodic Recertification of User Roles (TCP/CCM) Management is not recertifying the appropriateness of TCP/CCM user roles on a periodic basis.",  
    "CAR-T Proof of Delivery (POD) Invoice Delay Creation of new Treatment Centers (CTC) is not validated to confirm requisite fields have been applied to enable automatic invoicing after Proof of Delivery (POD)."  
  ],  
  "sample_recommendations": [  
    "We recommend management implement a more robust periodic user access review control for both TCP and COC/COI which would involve periodic recertification of internal and external users’ access by approvers familiar with the end-user base.",  
    "We recommend management implement a more robust periodic user access review control for both TCP and COC/COI which would involve periodic recertification of internal and external users’ access by approvers familiar with the end-user base and to disable user access after 6 months of inactivity.",  
    "We recommend management review and approve the appropriateness of the user roles and functionality on at least an annual basis in addition to ensuring roles are maintained through their change management process.",  
    "Management should establish and implement a recurring control to verify all active/new customers are set up correctly with necessary condition record(s) in Atlas."  
  ],  
  "sample_impact": [  
    "As a result: 13 out of 997 terminated J&J employees were granted roles within the system at go live in March 2023.",  
    "If an internal user's network credentials are disabled, they are unable to authenticate through Okta and therefore unable to access the application.",  
    "This could lead to further risk of inappropriate access in the user base through mismanagement, errors or malicious attacks.",  
    "Orders delivered without an invoice being generated could go undetected, causing revenue to be recognized in the incorrect period."  
  ],  
  "sample_root_cause": [  
    "Management had understood that the survey format of the review would meet requirements and had not fully considered J&J’s accountability of controls over all user access to J&J systems.",  
    "Management was relying on the roles still being assigned to appropriateness of TCP/CCM user roles.",  
    "The Customer Master data creation process has an insufficient control design given the manual process required to enable automatic invoicing."  
  ]  
}  


# In[2]:


#guidelines


issue_g = '''issue statement describes a control breakdown that results in unacceptable risk. An issue statement describes one of the following problems: • The control task is not done (could be missing or circumvented). • The control task is done, but in a flawed way. The issue statement should be the first sentence in the Detailed Issue. Even if you did not identify exceptions, you might still have a reportable issue.Who does not [descriptive words] do what. [Active voice]
9a.     Purchasing does not always approve changes to the vendor master file.
9b.     Finance does not review budget reports regularly.
What is not [descriptive words] done. [Passive voice]
9c.     Changes to the vendor master file are not always approved.
9d.     User access for terminated employees is not revoked within required 
timeframes. Avoid ensure, which means guarantee or make certain. Ensure is not a control.
• Avoid recommendation words (e.g., should, needs to, requires). 
• If needed for accuracy, add descriptive words around the verb. Consider flaws in 
frequency (e.g., not always, not regularly, not usually) and flaws in quality (e.g., not
thoroughly, not consistently). 
• Use present tense (e.g., does not, are not). Until the auditee corrects the issue and 
GA&A validates the correction, the residual risk remains unacceptable. 
• Write a complete sentence. 1. Use a tangible subject (i.e., who or what). 
2. Describe the control breakdown in the verb.
3. Write a complete sentence Avoid the phrase segregation of duties in the issue. It does not describe the control 
breakdown. Instead, use conflicting control verbs or conflicting subjects. You can highlight the 
conflict by using the word same or both. Consider using “Segregation of Duties” as the title. If the auditee does not follow or comply with a benchmark (e.g., policy, regulation, standard), 
describe the task that the auditee does not do.
To concisely link the issue to the benchmark, consider referencing the benchmark in 
parentheses within the issue statement. 
15.     Revenue reserves are not always calculated using data from the two most 
recent periods (WWP 210Ae). For full scope audits, avoid issues that focus on the following control elements or benchmarks:
• control • method • procedure
• framework • policy • process
These issues are not task specific, might be misinterpreted, and often mask a more serious 
control breakdown. When writing a consolidated issue, you still need to describe who does not do what or what 
is not done. 
Here are examples of consolidated issues.
18a.     Daily operations regarding XXX are not well managed.
18b.     Management does not closely oversee YYY.
18c.     The ABC files are not sufficiently secured.
18d.     Key operations regarding change control are not separated. Avoid unnecessary introductions (e.g., During our audit; GA&A identified; It is observed 
that). This applies to all of your writing, not just to issues.
• Avoid starting with there, there is no, or no (e.g., There is no approval of….). There is 
not tangible and no has an attacking tone.'''



root_g = '''If you identified flaws in the design or governance, but you continued testing and identified exceptions, report the flawed control element (e.g., poor design, incomplete procedures) as the root cause. To write the root cause(s), follow these guidelines:
• Write a complete sentence.
• Confirm that the subject of the sentence is tangible and business related. 
• Confirm that the verb expresses the action (i.e., the cause is actionable). Continue to 
avoid wasted verbs (e.g., perform, conduct).
• Avoid repeating or reporting control breakdowns or symptoms within the cause. 
• Avoid unnecessary introductions (e.g., The root cause of this issue is…).
• Avoid describing a detective control breakdown (e.g., oversight, supervision). If 
management does not effectively oversee or supervise a process, that might be a 
secondary issue. If a cause could embarrass the auditee (e.g., laziness, incompetence, poor management 
skills), consider one of the following “tactful” causes:
19a.     Competing priorities have delayed the completion of these tasks.
19b.     Management did not communicate to the staff the consequences of not doing 
these tasks correctly [or the importance of doing these tasks correctly].
19c.     Management has not developed an incentives and consequences program for 
the staff.
Be wary about reporting insufficient resources or budgets as the root cause. If the business 
insists insufficient resources or budgets is the root cause, consider one of the following 
approaches:
• Focus the root cause on insufficient prioritization of tasks. (See example 19a.)
• Start the root cause sentence with an attribution: “According to management, 
<resources or budgets are insufficient.>” Verify that management provides an action 
plan step that either resolves the cause or implements a compensating control that 
sufficiently mitigates the risk. Avoid unnecessary introductions (e.g., During our audit; GA&A identified; It is observed 
that). This applies to all of your writing, not just to issues.
• Avoid starting with there, there is no, or no (e.g., There is no approval of….). There is 
not tangible and no has an attacking tone.'''



impact_g = '''The impact statement serves the following key purposes:
• Convince readers that the issue is worth fixing (i.e., motivate action).
• Communicate the severity of the threat to the business.
• Support the issue rating (e.g., Critical, Major, Minor) in both content and tone.
Before writing the impact statement, read the issue statement and “think,” but do not write, 
as a result. Verify that the impact statement sufficiently answers the question “So what?” Go far 
enough to sell the value of resolving the issue, but do not oversell. Avoid unnecessary introductions (e.g., During our audit; GA&A identified; It is observed that). This applies to all of your writing, not just to issues. • Avoid starting with there, there is no, or no (e.g., There is no approval of….). There is not tangible and no has an attacking tone. Avoid obvious risks. Avoid risk categories (e.g., financial risk, regulatory risk, reputational risk).Avoid unauthorized, which is not specific. Avoid control breakdown language (e.g., might not monitor, might not review). If the 
impact statement includes control language, either the issue is not fully developed (i.e., 
the issue statement describes a root cause) or the control breakdown is repeated. Exception: If the issue is about a flawed control element (e.g., poor design, incomplete
framework), the impact statement will likely contain control breakdown language. In this 
case, the impact statement should go on to describe the threat to the business.Avoid jargon. For technical issues, identify the business risk.Who could [might] do what. [Active voice]
10a.     A knowledgeable vendor could divert funds into a personal account without 
detection.
What could [might] be done. [Passive voice]
10b.     Funds could be diverted into a personal account without detection.
Who may not [might not] do what. [Active voice]
10c.     The ABC Department might not be able to enforce contractual delivery 
requirements. 
What may not [might not] be done. [Passive voice]
10d.     Reports used to make scheduling decisions may not be reliable.Write the impact statement as a complete sentence.
• Avoid repeating the issue or the root cause (e.g., failure to reconcile, lack of
prioritization, without reviewing, absence of an analysis).
• As with issues, use a tangible, business-related subject. The subject can be the 
offender, the victim, or a business-related item. 
Offenders or Victims
a former employee, analysts, anyone who knows how to use the PAY-ME system, 
anyone with access to the data center, clients, consultants, customers, distributors, 
employees, investors, outside contractors, programmers, suppliers, users from other 
departments, users with conflicting responsibilities, users without a job need, vendors
Business-Related Items
accounts, acquisitions, adjustments, customer identity, data, expenses, inventory, 
leases, networks, payments, platforms, pricing tables, programs, reports, schedules, 
statements 
• Avoid wasted verbs (e.g., conduct, occur, perform). Instead, use specific, businessrelated risk verbs.
Business-Related Risk Verbs
abuse, be dissatisfied, cancel, corrupt, damage, delay, delete, deteriorate, distort, 
divert, embarrass, exploit, falsify, forge, hack, hold hostage (data), intercept, misapply, 
miscalculate, misjudge, misrepresent, misuse, not anticipate, not meet management’s 
intentions, not recover, offend, overcharge, publicize, redirect, sabotage, tamper with, 
undercharge. To further strengthen or soften the tone of the impact statement, use descriptive 
words around the subject or verb. Descriptive words allow you to use a strong verb 
(e.g., corrupt), yet still present the risk fairly (e.g., accidentally or deliberately corrupt). Use conditional helping verbs (e.g., could, might, might not, may not). However, avoid 
over-hedging (e.g., could potentially). Also, avoid may, which implies permission (e.g., 
Management may might breach conditions outlined in the request for proposal). 
• Avoid is and will. If a real event has already occurred demonstrating the risk, use the 
pattern has XX and could continue to XX (e.g., has overcharged and could continue to 
overcharge).
• Avoid the word risk in the impact statement (e.g., there is a risk that, the risk exists, this 
increases the risk that, are at risk of). Also, as you use an “Impact” caption, the word 
risk in the impact statement is redundant.
• To mitigate the risk, follow the impact statement with a sentence starting, however. A 
mitigating statement diminishes the severity of the risk. Avoid the phrase in mitigation, 
which is audit jargon. To intensify the risk, follow the impact statement with a sentence starting, this is 
compounded by. '''


recommendation_g = '''If the process, volumes, environment, inherent risk, and other factors do not change, 
risk will remain managed within the auditee’s and J&J’s risk appetite over time. 
• If these factors change and the auditee is aware of its risks, management should be 
able to change the controls proactively .Who should do what. [Active voice]
2a.     Management should approve the consignment scorecard monthly.
Do what. [Active voice – Imperative mood]
2b.     Approve the consignment scorecard monthly. 
To achieve these sentence patterns, follow these guidelines: 
• Use control verbs (e.g., approve, reconcile, verify) and avoid wasted verbs (e.g.,
perform, conduct, carry out, undertake).
• To resolve segregation of duties issues, consider the following verbs:
o Preclude – This emphasizes who must not do the task.
o Revoke – This is the same as preclude, but it is electronic.
o Assign – This describes who will do a new task.
o Reassign – This describes who must not do an existing task and who will now do
the existing task.
• Avoid the verb ensure. Ensure means make certain or guarantee, so it is not a control 
and is not measurable.
• Avoid we recommend, which is redundant with the Recommendation caption. 
• Limit phrases such as develop a process, implement a procedure, and put a process in 
place. These phrases are not specific and are too hard to measure. What should they 
do? 
• If the action cannot be implemented soon enough to restore risk to an acceptable 
tolerance level, include a workaround (e.g., Until then, the supervisor should XX).
• For short-term (tactical) and long-term (strategic) action plans, verify that milestone 
dates are realistic. Avoid unnecessary introductions (e.g., During our audit; GA&A identified; It is observed that). This applies to all of your writing, not just to issues. • Avoid starting with there, there is no, or no (e.g., There is no approval of….). There is not tangible and no has an attacking tone.'''


# In[3]:


issues =''' {"issue_statement":['encryption for Data at Rest
Encryption for data at rest, residing on fourth-party data 
centers, has not been enabled for the IRIS as required in 
the IAPPs for systems with Highly Restricted Data. Per 
the Compliance Analysis, in aggregate, the information 
housed in IRIS is classified as Highly Restricted, based 
on the risks associated with aggregating data that 
represents most J&J IT systems. This data includes 
server and network device names, IP addresses, CI 
criticality and security incident details/potential 
vulnerabilities.
Additionally, IRIS currently holds PII – Type 2 (home 
address) employee data due to Covid-19 work-fromhome mandates and the need to obtain employee 
addresses to ship laptops, resulting in potential GDPR 
non-compliance.]}'''


# In[4]:


# data_rootcause = "sample_issues = ( " + str(sample_data['sample_issues']) +") sample_root_cause = (" + str(sample_data['sample_root_cause']) +") issue_statement= ("+ str(issue['issue_statement'] ) 


# data_impact = "sample_issues = ( " + str(sample_data['sample_issues']) +") sample_impact= (" + str(sample_data['sample_impact']) +") issue_statement= ("+ str(issue['issue_statement'] ) 

# data_recommendation  = "sample_issues = ( " + str(sample_data['sample_issues']) +") sample_recommendations = (" + str(sample_data['sample_recommendations']) +") issue_statement= ("+ str(issue['issue_statement'] ) 



# In[5]:


data_rootcause


# In[ ]:





# In[6]:


import pprint  
import urllib.parse  
import json5  
import openai  
from qwen_agent.agents import Assistant  
from qwen_agent.tools.base import BaseTool, register_tool  
from qwen_agent import Agent  
import os  
import re  
from PyPDF2 import PdfFileReader  
import logging
  
os.environ['AZURE_OPENAI_API_KEY'] = ""  
os.environ['AZURE_OPENAI_ENDPOINT'] = "https://mlopscoe-openai.openai.azure.com/"  
  
llm_cfg = {  
    'model': 'gpt-4o-retrieval',  
    'azure_endpoint': os.getenv('AZURE_OPENAI_ENDPOINT'),  # base_url, also known as api_base  
    'api_key': os.getenv('AZURE_OPENAI_API_KEY'),  
    'generate_cfg': {  
        'top_p': 0.8  
    }  
}  
  
@register_tool('pdf_analyzer_policy')  
class PDFAnalyzer(BaseTool):  
    description = 'Tool to analyze PDF files containing policy guidelines, identify policy violations in provided issue statements, and rewrite the issue statements.'  
  
    parameters = [  
        {  
            'name': 'pdf_paths',  
            'type': 'list',  
            'description': 'List of paths to the PDF files',  
            'required': True  
        },  
        {  
            'name': 'issue_statement',  
            'type': 'string',  
            'description': 'The issue statement to be analyzed',  
            'required': True  
        }  
    ]  
  
    def call(self, params: str, **kwargs) -> str:  
        params = json5.loads(params)  
        pdf_paths = params['pdf_paths']  
        issue_statement = params['issue_statement']  
        policy_guidelines = self.extract_pdf_content(pdf_paths)  
        analyzed_statement = self.analyze_statement(policy_guidelines, issue_statement)  
        return json5.dumps({'analyzed_statement': analyzed_statement}, ensure_ascii=False)  
  
    def extract_pdf_content(self, pdf_paths: list):  
        policy_guidelines = []  
        for pdf_path in pdf_paths:  
            with open(pdf_path, 'rb') as file:  
                reader = PdfFileReader(file)  
                for page_num in range(reader.numPages):  
                    page = reader.getPage(page_num)  
                    text = page.extract_text()  
                    policy_guidelines += re.findall(r'Policy Guideline:\s*(.*)', text)  
        return policy_guidelines  
  
    def analyze_statement(self, policy_guidelines: list, issue_statement: str):  
        violations = [guideline for guideline in policy_guidelines if guideline in issue_statement]  
        if violations:  
            new_statement = f"Revised Statement: {issue_statement} (Violations: {', '.join(violations)})"  
        else:  
            new_statement = f"No violations found in statement: {issue_statement}"  
        return new_statement 
    

@register_tool('pdf_root_cause')  
class PDFAnalyzer(BaseTool):  
    description = 'Tool to analyze PDF files containing sample audit reports and standards violations , based on this predict the root cause '  
  
    parameters = [  
        {  
            'name': 'pdf_paths',  
            'type': 'list',  
            'description': 'List of paths to the PDF files',  
            'required': True  
        },  
        {  
            'name': 'issue_statement',  
            'type': 'string',  
            'description': 'The text to be analyzed',  
            'required': True  
        }  
    ]  
  
    def call(self, params: str, **kwargs) -> str:  
        params = json5.loads(params)  
        pdf_paths = params['pdf_paths']  
        text = params['issue_statement']  
        sample = self.extract_pdf_content(pdf_paths)  
        analyzed_statement = self.analyze_statement(sample, text)  
        return json5.dumps({'analyzed_statement': analyzed_statement}, ensure_ascii=False)  
  
    def extract_pdf_content(self, pdf_paths: list):  
        policy_guidelines = []  
        for pdf_path in pdf_paths:  
            with open(pdf_path, 'rb') as file:  
                reader = PdfFileReader(file)  
                for page_num in range(reader.numPages):  
                    page = reader.getPage(page_num)  
                    text = page.extract_text()  
                    policy_guidelines += re.findall(r'Policy Guideline:\s*(.*)', text)  
        return policy_guidelines  
  
    def analyze_statement(self, sample: list, text: str):  
        violations = [guideline for guideline in sample if guideline in text]  
        if violations:  
            new_statement = f"Revised Statement: {text} (Violations: {', '.join(violations)})"  
        else:  
            new_statement = f"No violations found in statement: {text}"  
        return new_statement     
    
    
    
@register_tool('pdf_analyzer_language')  
class PDFAnalyzer(BaseTool):  
    description = 'Tool to analyze PDF files containing language guidelines, identify violations in provided text, and rewrite the text.'  
  
    parameters = [  
        {  
            'name': 'pdf_paths',  
            'type': 'string',  
            'description': 'List of paths to the PDF files',  
            'required': True  
        },  
        {  
            'name': 'text',  
            'type': 'string',  
            'description': 'The text to be analyzed',  
            'required': True  
        }  
    ]  
  
    def call(self, params: str, **kwargs) -> str:  
        params = json5.loads(params)  
        pdf_paths = params['pdf_paths']  
        text = params['text']  
        lang_guideline = self.extract_pdf_content(pdf_paths)  
        analyzed_statement = self.analyze_statement(lang_guideline, text)  
        return json5.dumps({'analyzed_statement': analyzed_statement}, ensure_ascii=False)  
  
    def extract_pdf_content(self, pdf_paths: list):  
        policy_guidelines = []  
        for pdf_path in pdf_paths:  
            with open(pdf_path, 'rb') as file:  
                reader = PdfFileReader(file)  
                for page_num in range(reader.numPages):  
                    page = reader.getPage(page_num)  
                    text = page.extract_text()  
                    policy_guidelines += re.findall(r'Policy Guideline:\s*(.*)', text)  
        return policy_guidelines  
  
    def analyze_statement(self, lang_guideline: list, text: str):  
        violations = [guideline for guideline in lang_guideline if guideline in text]  
        if violations:  
            new_statement = f"Revised Statement: {text} (Violations: {', '.join(violations)})"  
        else:  
            new_statement = f"No violations found in statement: {text}"  
        return new_statement 
    
    
import json5  
import re  
from PyPDF2 import PdfFileReader  
  
@register_tool('PDF')  
class PDF_Extract_data(BaseTool):  
    description = 'Tool to analyze PDF files containing sample audit reports and standards violations, and predict the root cause, impact, and recommendations'  
      
    parameters = [  
        {  
            'name': 'pdf_paths',  
            'type': 'list',  
            'description': 'List of paths to the PDF files',  
            'required': True  
        },  
        {  
            'name': 'issue_statement',  
            'type': 'string',  
            'description': 'The text to be analyzed',  
            'required': True  
        }  
    ]  
      
    def call(self, params: str, **kwargs) -> str:  
        params = json5.loads(params)  
        pdf_paths = params['pdf_paths']  
        text = params['issue_statement']  
        sample = self.extract_pdf_content(pdf_paths)  
        analyzed_sections = self.analyze_statement(sample, text)  
        return json5.dumps(analyzed_sections, ensure_ascii=False)  
      
    def extract_pdf_content(self, pdf_paths: list) -> dict:  
        content = {'root_cause': [], 'impact': [], 'recommendations': [], 'issue': []}  
        for pdf_path in pdf_paths:  
            with open(pdf_path, 'rb') as file:  
                reader = PdfFileReader(file)  
                for page_num in range(reader.numPages):  
                    page = reader.getPage(page_num)  
                    text = page.extract_text()  
                    content['root_cause'] += re.findall(r'Root Cause:\s*(.*)', text)  
                    content['impact'] += re.findall(r'Impact:\s*(.*)', text)  
                    content['recommendations'] += re.findall(r'Recommendations:\s*(.*)', text)  
                    content['issue'] += re.findall(r'Issue:\s*(.*)', text)  
        return content  
      
    def analyze_statement(self, sample: dict, text: str) -> dict:  
        root_cause = [item for item in sample['root_cause'] if item in text]  
        impact = [item for item in sample['impact'] if item in text]  
        recommendations = [item for item in sample['recommendations'] if item in text]  
        issue = [item for item in sample['issue'] if item in text]  
          
        analyzed_sections = {  
            'root_cause': root_cause if root_cause else 'No root cause found in statement',  
            'impact': impact if impact else 'No impact found in statement',  
            'recommendations': recommendations if recommendations else 'No recommendations found in statement',  
            'issue': issue if issue else 'No issue found in statement'  
        }  
          
        return analyzed_sections  
    
    
    


# In[106]:


system_instruction_root_cause_analysis = '''Analyze the provided PDF to identify relevant policy guidelines, review the sample issue statement and root cause, check for policy violations, and generate the root cause for the given issue statement.

# Steps

1. **Analyze PDF**: 
   - Read through the provided PDF document.
   - Extract and summarize any relevant policy guidelines. 

2. **Review Sample Issue**: 
   - Examine the sample issue statement.
   - Understand the root cause associated with the sample issue.

3. **Check for Policy Violations**:
   - Cross-reference the issue statement against the extracted policy guidelines.
   - Determine if there are any policy violations present.

4. **Generate Root Cause**:
   - Analyze the given issue statement.
   - Formulate the root cause based on the analysis and cross-referencing of policy guidelines.

# Output Format

- A brief summary of any relevant policy guidelines from the PDF.
- A statement indicating whether any policy violations are found.
- A detailed explanation of the generated root cause for the given issue.

# Notes

- Ensure accuracy when identifying policy guidelines and potential violations.
- Provide clear and structured explanations for each step.
- Maintain confidentiality and do not disclose any sensitive information from the PDF document.'''


system_instruction_recommendation_analysis = '''Provide a recommendation based on the given issue statement, impact, and root cause, ensuring compliance with the language guidelines specified in section "recommendation_g" of the guideline PDF.

# Steps

1. **Understand the Inputs**:
   - *Issue Statement*: Identify the primary concern or problem.
   - *Impact*: Recognize the consequence or effect of the issue.
   - *Root Cause*: Determine the underlying reason(s) for the issue.

2. **Generate Recommendation**:
   - Derive actionable steps or solutions focused on addressing the root cause.
   - Ensure that the recommendation is practical, specific, and targeted at mitigating the impact of the issue.
   - Verify that the recommendation adheres to the language guidelines in section "recommendation_g" of the provided guidelines PDF.

3. **Review Compliance**: Double-check the recommendation against the guideline to ensure it does not contain language or suggestions that are prohibited or discouraged.

# Output Format

- A paragraph that includes a clearly defined recommendation, followed by a brief explanation of how this recommendation addresses the root cause and its expected impact.


- **Output**:
  - Recommendation: "Enhance packaging with reinforced materials such as bubble wrap or foam padding, and conduct drop tests to ensure durability."
  - Explanation: "Improving packaging protection will reduce the likelihood of damage during shipping, thereby decreasing customer complaints and returns."

# Notes

- Verify that any recommendation does not contradict section "recommendation_g" of the language guidelines by ensuring it uses appropriate tone and language.
- If unsure about compliance, consult the guideline PDF directly to ensure adherence.'''



system_instruction_impact_analysis = '''Analyze the provided PDF to identify any relevant policy guidelines, review the sample issue statement along with its impacts, check for any policy violations according to the guidelines in the PDF, and finally generate the impact for the given issue statement.

# Steps

1. **Analyze PDF**: Examine the provided PDF to extract any relevant policy guidelines.
2. **Review Issue Statement**: Carefully consider the provided sample issue statement and its impact.
3. **Check for Policy Violations**: Compare the impact against the identified policy guidelines to determine any violations.
4. **Generate impact**: Based on your analysis, generate a precise impact for the given issue statement considering any policy guidelines and potential violations.

# Output Format

Provide an analysis in paragraph, clearly stating findings.
# Notes

- Ensure that all findings are backed by specific references to policy guidelines where applicable.
- Pay close attention to nuanced details in policy guidelines to ensure accurate identification of violations.'''

system_instruction_extract_sections = '''You are a helpful assistant. After receiving the user's request, you should:

First, analyze the provided PDF to identify and extract specific sections such as issue, recommendations, impact, and root cause.
Ensure that each section is clearly identified and separated in the response.
Return the extracted information as a structured response, mapping it into a data structure containing separate lists for issue, recommendations, impact, and root cause. and make sure you dont cut any data it should be full and intact"

Data Structure Example:

{  
  "issue": ["Issue details here"],  
  "recommendations": ["Recommendation details here"],  
  "impact": ["Impact details here"],  
  "root_cause": ["Root cause details here"]  
}  
'''


SI_recommendation = '''Follow the guidelines outlined in the "recommendation_g" section of the provided PDF to rewrite the given recommendation statement. Ensure clarity, concise language, and adherence to the specified format and tone as described in the guidelines.

# Steps

1. **Read the Original Recommendation**: Thoroughly understand the content and intent of the original statement.
2. **Extract Key Points**: Identify the main points, objectives, and any specific details mentioned in the original recommendation.
3. **Review the Guidelines**: Refer to the "recommendation_g" section to understand the required structure, style, and any specific language to use.
4. **Rewrite**: Based on the understanding of both the original statement and the guidelines, rewrite the recommendation, ensuring it aligns with the required format and tone.
5. **Proofread**: Review the rewritten recommendation for clarity, coherence, and adherence to guidelines.

# Output Format

- The rewritten recommendation should be presented as a concise, well-structured statement.
- Use formal language as specified in the guidelines, ensuring all key points are effectively communicated.

# Notes

- Ensure that the rewritten recommendation maintains the intent and purpose of the original statement while aligning with the provided guidelines.
- Pay particular attention to any specific phrases or terms the guidelines emphasize or discourage.'''



SI_impact = '''Rewrite the provided impact statement according to the guidelines specified in the "impct_g" section of the guidelines PDF.

# Steps

- Review the original impact statement provided in the input.
- Refer to the "impct_g" section in the guidelines PDF to identify key elements and structure required for an impact statement.
- Revise the impact statement to align with these guidelines, focusing on clarity, specificity, and relevance.

# Output Format

- Provide a concise rewritten "impact" statement.
- Ensure the language, tone, and structure align with the "root_g" guidelines.

# Notes

- Make sure to address any specific examples or data required by the guidelines.
- Keep the revised statement relevant to the context and objectives provided in the input.'''


SI_root = '''Provide a rewritten version of the "root_cause" statement tailored based on the guidelines and specific details outlined in the "root_g" section of the language guideline PDF.

# Steps

1. Review the "root_g" section from the guideline PDF to understand the necessary language, tone, and structure.
2. Identify key elements required in the "root_cause" statement according to these guidelines.
3. Rewrite the "root_cause" statement incorporating the specified details and adhering to the stylistic and content requirements outlined in "root_g."

# Output Format

- Provide a concise rewritten "root_cause" statement.
- Ensure the language, tone, and structure align with the "root_g" guidelines.


# Notes

- Ensure that all critical aspects from the "root_g" section are considered.
- Maintain clarity and precision in conveying the root cause.'''




SI_issue = '''You want to rewrite the issue statement from a PDF document according to specific guidelines found in the "issue_g" sections of the same document. To proceed effectively, ensure you follow these steps:

1. **Open and Read the PDF**: Locate the relevant PDF document and navigate to the sections containing "issue_g."

2. **Understand the Guidelines**: Carefully read and comprehend the guidelines provided in the "issue_g" sections. Make note of key points, such as language style, structure, and any specific requirements for rewriting the issue statement.

3. **Locate the Issue Statement**: Identify the original issue statement within the document.

4. **Rewrite the Issue Statement**: Utilize the guidelines from "issue_g" to revise the original issue statement. Pay attention to tone, clarity, and context, ensuring that the revised statement aligns with the specified criteria.

5. **Review and Edit**: Review the rewritten statement to ensure it meets all the guidelines and is clear and concise.

6. **Verify Compliance**: Double-check that the rewritten statement fully adheres to the guidelines and captures the essence of the original issue accurately.

If you need further assistance or specific details about rewriting without access to the PDF itself, let me know the content or any snippets from the issue and the guidelines from the "issue_g" sections, and I'd be happy to help further.'''


system_instruction_root_cause_analysis = '''You are a helpful assistant. After receiving the user's request, you should:  
- First, analyze the provided audit reports PDF to identify any findings and relevant details.  
- Then, review the standard violations PDF to understand the established guidelines and standards.  
- Next, examine the input issue statement to determine the context and specifics of the problem.  
- Finally, correlate the information from the audit reports and standard violations with the issue statement to predict the root cause of the problem.  
'''

system_instruction_language_guideline = '''You are a helpful assistant. After receiving the input, you should:  
- First, analyze the provided PDF to identify language guidelines.  
- Then, review the given text to find any deviations from the language guidelines in the PDF.  
- Finally, rewrite the text to align with the identified language guidelines, ensuring it adheres to the instructions provided in the PDF.  
'''  
  
pdftools_policy = ['pdf_analyzer_policy']  
files_policy_auditreport1 = ['./examples/resource/impact/BIS.pdf' , './examples/resource/impact/NIST.pdf' , './examples/resource/impact/COBIT.pdf' , './examples/resource/impact/owasp.pdf']  

lang_guideline = ['./examples/resource/data.xlsx' ]

files_policy_auditreport = ['./examples/resource/BIS.pdf' , './examples/resource/NIST.pdf' , './examples/resource/COBIT.pdf' , './examples/resource/owasp.pdf']  

guideline_doc = ['./examples/resource/guidelines.pdf']

pdfextract_tool = ['PDF']
pdf_rootcause_tool = ['pdf_analyzer_policy']
files_audit_example = ['./examples/resource/audit/auditsample.pdf']
  
root_bot = Assistant(  
    llm=llm_cfg,  
    system_message=system_instruction_root_cause_analysis,  
    # function_list=pdf_rootcause_tool,  
    files=files_policy_auditreport  
)  



impact_bot = Assistant(  
    llm=llm_cfg,  
    system_message=system_instruction_impact_analysis,  
    # function_list=pdftools_policy,  
    files=files_policy_auditreport1  
)  


recommendation_bot = Assistant(  
    llm=llm_cfg,  
    system_message=system_instruction_recommendation_analysis,  
    # function_list=pdftools_policy,  
    files=files_policy_auditreport  
) 

pdftools_root = ['pdf_root_cause']


# Language_guideline_bot = Assistant(  
#     llm=llm_cfg,  
#     system_message=system_instruction_language_guideline,  
#     function_list=pdfextract_tool,  
#     files=  lang_guideline
# ) 


issue_lang_filter = Assistant(  
    
    llm=llm_cfg,  
    system_message=SI_issue,  
    # function_list=pdfextract_tool,  
    files=guideline_doc  
)  


impact_lang_filter = Assistant(  
    
    llm=llm_cfg,  
    system_message=SI_impact,  
    # function_list=pdfextract_tool,  
    files=guideline_doc  
)

root_lang_filter = Assistant(  
    
    llm=llm_cfg,  
    system_message=SI_root,  
    # function_list=pdfextract_tool,  
    files=guideline_doc  
)

recommendation_lang_filter = Assistant(  
    
    llm=llm_cfg,  
    system_message=SI_recommendation,  
    # function_list=pdfextract_tool,  
    files=guideline_doc  
)





bot1 = Assistant(  
    llm=llm_cfg,  
    system_message=system_instruction_extract_sections,  
    function_list=pdfextract_tool,  
    files=files_audit_example  
)  






def extract_rewritten_statement(messages):  
    for message in messages:  
        if message['role'] == 'assistant':  
            content = message['content']  
            match = re.search(r'Rewritten Issue Statement:\s*(.*)', content, re.DOTALL)  
            if match:  
                return match.group(1).strip()  
    return None  
  
# Extract the rewritten issue statement  


# In[60]:


#rewrite the issue statement

messages = []  
  
# Step 2: User query  
query = input('user query: ')  
messages.append({'role': 'user', 'content': issues})  

x = []
for response in issue_lang_filter.run(messages=messages):  
    # pprint.pprint(response, indent=2)  
    x.extend(response)


# In[61]:


rewritten_issue = response[-1]['content']


# In[62]:


issues = response[-1]['content']
issues


# In[63]:


data_rootcause = "sample_issues = ( " + str(sample_data['sample_issues']) +") sample_root_cause = (" + str(sample_data['sample_root_cause']) +") issue_statement= (" + issues 


data_impact = "sample_issues = ( " + str(sample_data['sample_issues']) +") sample_impact= (" + str(sample_data['sample_impact']) +") issue_statement= ("+  issues 




# In[64]:


data_rootcause


# In[86]:


# Step 1: Initialize the messages list  root_cause 
messages_root = []  
messages_impact = []  
messages_recommendation = []  
# Step 2: User query  
query = input('user query: ')  


messages_root.append({'role': 'user', 'content': data_rootcause})  




messages_impact.append({'role': 'user', 'content': data_impact})  


  

messages_recommendation.append({'role': 'user', 'content': data_recommendation})  
  
# Step 3: Run the root_bot and save its response in gen_root  
x = []
for response_root in root_bot.run(messages=messages_root):  
    # pprint.pprint(response, indent=2)  
    x.extend(response)
    

    
    
    
for response_impact in impact_bot.run(messages=messages_impact):  
    # pprint.pprint(response, indent=2)  
    x.extend(response)    
    
for response_recommendation in recommendation_bot.run(messages=messages_recommendation):  
    # pprint.pprint(response, indent=2)  
    x.extend(response)    
    
    
# messages.extend(response)     
    


# In[87]:


content_root = response_root[-1]['content']
content_root


# In[88]:


content_impact = response_impact[-1]['content']
content_impact


# In[89]:


response_recommendation


# In[90]:


content_recommendation = response_recommendation[-1]['content']
content_recommendation


# In[ ]:





# In[91]:


root_cause_start = content_root.find("Predicted Root Cause")  
# root_cause_end = text.find("Correlated Root Cause")  
  
predicted_root_cause_section = content_root[root_cause_start:].strip()  


# In[92]:


predicted_root_cause_section


# In[93]:


impact_start = content_impact.find("Impact Generation:")  
 
  
predicted_impact_section = content_impact[impact_start:].strip()  
predicted_impact_section


# In[94]:


recommendation_start = content_recommendation.find("Generated Impact:")  
 
  
predicted_recommendation_section = content_recommendation[impact_start:].strip()  
predicted_recommendation_section


# In[ ]:





# In[ ]:





# In[ ]:





# In[101]:


messages_root = []  
messages_impact = []  
# Step 2: User query  
query = input('user query: ')  
messages_root.append({'role': 'user', 'content': predicted_root_cause_section})  

messages_impact.append({'role': 'user', 'content': predicted_impact_section})  
# Step 3: Run the root_bot and save its response in gen_root  
x = []
for response_root in root_lang_filter.run(messages=messages_root):  
    # pprint.pprint(response, indent=2)  
    x.extend(response)
    
for response_impact in impact_lang_filter.run(messages=messages_impact):  
    # pprint.pprint(response, indent=2)  
    x.extend(response)    


# In[102]:


response_impact[-1]['content']


# In[103]:


response_root[-1]['content']


# In[104]:


filtered_predicted_root_cause = response_root[-1]['content']
filtered_predicted_impact = response_impact[-1]['content']
filtered_predicted_root_cause


# In[107]:


data_recommendation  = "issue = ( " + issues +") , impact = ( "+ filtered_predicted_impact + ") , root cause = ("  + filtered_predicted_root_cause + ")" 


# In[108]:


messages = []  

# Step 2: User query  


messages.append({'role': 'user', 'content': data_recommendation})  
# Step 3: Run the root_bot and save its response in gen_root  
x = []
for response in recommendation_lang_filter.run(messages=messages):  
    # pprint.pprint(response, indent=2)  
    x.extend(response)


# In[111]:


generated_recommendation = response[-1]['content']

generated_recommendation


# In[35]:


filtered_root = []  
for response1 in Language_guideline_bot.run(messages=messages):  
    pprint.pprint(response1, indent=2)  
    filtered_root.extend(response1)     
    
  
# # Step 4: Update messages with root_bot's response for further context if needed  
# i_data = []
# i_data.append({'role': 'user', 'content': data_impact})  
# messages.extend(gen_root)
# messages.extend(i_data)  

# print("____________________________________________________________________________________________________________________________________________________________________________________________________________")
# # Step 5: Run the impact_bot and save its response in gen_impact  
# gen_impact = []  
# for response in impact_bot.run(messages=messages):  
#     pprint.pprint(response, indent=2)  
#     gen_impact.extend(response)  
  
# # Output the final responses  
# print("Root Bot Response:")  
# pprint.pprint(gen_root, indent=2)  
  
# print("Impact Bot Response:")  
# pprint.pprint(gen_impact, indent=2) 










#------------------------------------------------------------------------------------------------------------














# # Step 4: Run the agent as a chatbot.  
# messages = []  # This stores the chat history.  

# while True:  
#     query = input('user query: ')  
    
#     messages.append({'role': 'user' , 'content':data_impact})  
    
#     # # response = []  
#     # count = 0
#     # for response in bot.run(messages = messages):
#     #     pprint.pprint(response, indent=2)
           
    
    
    
    
    
#     count = 0
#     for response1 in impact_bot.run(messages=messages):  
#         # print('')
#         resp = response1
#         pprint.pprint(response1, indent=2)
       
       
#     messages.extend(response1)
# #     rewritten_statement = extract_rewritten_statement(messages)
# #     rewritten_issue = messages
# #     messages = []
    
   
#     messages.append({'role': 'user', 'content': rewritten_statement})  
#     for response2 in bot1.run(messages = messages):
#         final_resp = response2
#         pprint.pprint(response2, indent=2)
        
#     messages.extend(response2)
        
#     # print(messages[response1])


# In[ ]:


# messages
# 


# In[ ]:


# gen_root


# In[9]:


def extract_data(data):  
    for item in data:  
        if item['role'] == 'assistant':  
            content = item['content']  
            sections = content.split('###')  
            structured_data = {}  
            for section in sections:  
                if section.strip():  
                    section_title, section_content = section.split('\n', 1)  
                    structured_data[section_title.strip()] = section_content.strip()  
            return structured_data  
  
# Extract and print the structured data  
structured_data = extract_data(messages)  
for key, value in structured_data.items():  
    print(f"{key}:\n{value}\n")  


# In[9]:


# Function to extract, clean, and save data into a list of strings  
def extract_and_clean_data(data):  
    cleaned_data = []  
    for item in data:  
        if item['role'] == 'assistant':  
            content = item['content']  
            sections = content.split('###')  
            for section in sections:  
                if section.strip():  
                    section_title, section_content = section.split('\n', 1)  
                    cleaned_data.append(f"{section_title.strip()}:\n{section_content.strip()}")  
    return cleaned_data  
  
# Extract, clean, and save the data  
cleaned_data = extract_and_clean_data(messages)  
  
# Print the cleaned data  
for entry in cleaned_data:  
    print(entry)  
    print()  
  
# Save the cleaned data into a list of strings  
cleaned_data_list = [entry for entry in cleaned_data]  
  
# Print the list of strings  
cleaned_data_l


# In[22]:


# #playing with faiss




# !pip install faiss-cpu
# !pip install sentence-transformers




# In[28]:


import pandas as pd
data = [[    "Periodic Access Review – (COC/COI) Management’s existing recertification and termination controls for COC/COI do not consistently detect terminated employees.",  
 "We recommend management implement a more robust periodic user access review control for both TCP and COC/COI which would involve periodic recertification of internal and external users access by approvers familiar with the end-user base.",  
     "As a result: 13 out of 997 terminated J&J employees were granted roles within the system at go live in March 2023.",  
   "Management had understood that the survey format of the review would meet requirements and had not fully considered J&J’s accountability of controls over all user access to J&J systems." 
 ],
[    "Periodic Access Review - External Users (TCP) The periodic access review for users of TCP at the Treatment Centers (external to J&J) does not currently require independent confirmation of appropriateness of access.",  
   "We recommend management implement a more robust periodic user access review control for both TCP and COC/COI which would involve periodic recertification of internal and external users’ access by approvers familiar with the end-user base and to disable user access after 6 months of inactivity.",  
   "If an internal user's network credentials are disabled, they are unable to authenticate through Okta and therefore unable to access the application.",  
    "Management was relying on the roles still being assigned to appropriateness of TCP/CCM user roles."  
],
[    "Periodic Recertification of User Roles (TCP/CCM) Management is not recertifying the appropriateness of TCP/CCM user roles on a periodic basis.",  
     "We recommend management review and approve the appropriateness of the user roles and functionality on at least an annual basis in addition to ensuring roles are maintained through their change management process.",  
    "This could lead to further risk of inappropriate access in the user base through mismanagement, errors or malicious attacks.",  
    "The Customer Master data creation process has an insufficient control design given the manual process required to enable automatic invoicing."  
]]
df = pd.DataFrame(data, columns = ['issue', 'recommendations' , 'impact' , 'root_cause'])


# In[29]:


df


# In[30]:


from sentence_transformers import SentenceTransformer
text = df['text']
encoder = SentenceTransformer("paraphrase-mpnet-base-v2")
vectors = encoder.encode(text)


# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:





# In[ ]:


sample_data = {  
  "sample_issues": [  
    "Periodic Access Review – (COC/COI) Management’s existing recertification and termination controls for COC/COI do not consistently detect terminated employees.",  
    "Periodic Access Review - External Users (TCP) The periodic access review for users of TCP at the Treatment Centers (external to J&J) does not currently require independent confirmation of appropriateness of access.",  
    "Periodic Recertification of User Roles (TCP/CCM) Management is not recertifying the appropriateness of TCP/CCM user roles on a periodic basis.",  
    "CAR-T Proof of Delivery (POD) Invoice Delay Creation of new Treatment Centers (CTC) is not validated to confirm requisite fields have been applied to enable automatic invoicing after Proof of Delivery (POD)."  
  ],  
  "sample_recommendations": [  
    "We recommend management implement a more robust periodic user access review control for both TCP and COC/COI which would involve periodic recertification of internal and external users’ access by approvers familiar with the end-user base.",  
    "We recommend management implement a more robust periodic user access review control for both TCP and COC/COI which would involve periodic recertification of internal and external users’ access by approvers familiar with the end-user base and to disable user access after 6 months of inactivity.",  
    "We recommend management review and approve the appropriateness of the user roles and functionality on at least an annual basis in addition to ensuring roles are maintained through their change management process.",  
    "Management should establish and implement a recurring control to verify all active/new customers are set up correctly with necessary condition record(s) in Atlas."  
  ],  
  "sample_impact": [  
    "As a result: 13 out of 997 terminated J&J employees were granted roles within the system at go live in March 2023.",  
    "If an internal user's network credentials are disabled, they are unable to authenticate through Okta and therefore unable to access the application.",  
    "This could lead to further risk of inappropriate access in the user base through mismanagement, errors or malicious attacks.",  
    "Orders delivered without an invoice being generated could go undetected, causing revenue to be recognized in the incorrect period."  
  ],  
  "sample_root_cause": [  
    "Management had understood that the survey format of the review would meet requirements and had not fully considered J&J’s accountability of controls over all user access to J&J systems.",  
    "Management was relying on the roles still being assigned to appropriateness of TCP/CCM user roles.",  
    "The Customer Master data creation process has an insufficient control design given the manual process required to enable automatic invoicing."  
  ]  
}  


# In[ ]:





# In[ ]:





# In[7]:


"""A multi-agent cooperation example implemented by router and assistant"""

import os
from typing import Optional

from qwen_agent.agents import Assistant, ReActChat, Router
from qwen_agent.gui import WebUI

ROOT_RESOURCE = os.path.join(os.path.dirname(__file__), 'resource')


def init_agent_service():
    # settings
    llm_cfg = {'model': 'qwen-max'}
    llm_cfg_vl = {'model': 'qwen-vl-max'}
    tools = ['image_gen', 'code_interpreter']

    # Define a vl agent
    bot_vl = Assistant(llm=llm_cfg_vl, name='多模态助手', description='可以理解图像内容。')

    # Define a tool agent
    bot_tool = ReActChat(
        llm=llm_cfg,
        name='工具助手',
        description='可以使用画图工具和运行代码来解决问题',
        function_list=tools,
    )

    # Define a router (simultaneously serving as a text agent)
    bot = Router(
        llm=llm_cfg,
        agents=[bot_vl, bot_tool],
    )
    return bot


def test(
        query: str = 'hello',
        image: str = 'https://dashscope.oss-cn-beijing.aliyuncs.com/images/dog_and_girl.jpeg',
        file: Optional[str] = os.path.join(ROOT_RESOURCE, 'poem.pdf'),
):
    # Define the agent
    bot = init_agent_service()

    # Chat
    messages = []

    if not image and not file:
        messages.append({'role': 'user', 'content': query})
    else:
        messages.append({'role': 'user', 'content': [{'text': query}]})
        if image:
            messages[-1]['content'].append({'image': image})
        if file:
            messages[-1]['content'].append({'file': file})

    for response in bot.run(messages):
        print('bot response:', response)


def app_tui():
    # Define the agent
    bot = init_agent_service()

    # Chat
    messages = []
    while True:
        query = input('user question: ')
        # Image example: https://dashscope.oss-cn-beijing.aliyuncs.com/images/dog_and_girl.jpeg
        image = input('image url (press enter if no image): ')
        # File example: resource/poem.pdf
        file = input('file url (press enter if no file): ').strip()
        if not query:
            print('user question cannot be empty！')
            continue
        if not image and not file:
            messages.append({'role': 'user', 'content': query})
        else:
            messages.append({'role': 'user', 'content': [{'text': query}]})
            if image:
                messages[-1]['content'].append({'image': image})
            if file:
                messages[-1]['content'].append({'file': file})

        response = []
        for response in bot.run(messages):
            print('bot response:', response)
        messages.extend(response)


def app_gui():
    bot = init_agent_service()
    chatbot_config = {
        'verbose': True,
    }
    WebUI(bot, chatbot_config=chatbot_config).run()


if __name__ == '__main__':
    # test()
    # app_tui()
    app_gui()


# In[ ]:





