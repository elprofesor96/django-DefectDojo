from dojo.models import Finding
import json

class WizDockerParser(object):
    def get_scan_types(self):
        return ["Wiz Docker Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Wiz Docker Scan"
        
    def get_description_for_scan_types(self, scan_type):
        return "Import wiz docker scan json from CI/CD wizcli, wizcli docker -i image"

    def get_findings(self, file, test):
        data = file.read()
        ### Aux
        toJSON = None
        #with open(file, "r") as fl:
        #    data = fl.read()
        #fl.close()
        try:
            toJson = json.loads(str(data, "utf-8"))
        except:
            toJson = json.loads(data)

        if toJson:
            if isinstance(toJson, dict):
                ### result obj -> osPackages_list
                result_obj = toJson.get('result')
                osPackages_list = result_obj.get('osPackages')
                findings = []
                forDefectDojo = []
                for package in osPackages_list:
                    package_name = package['name']
                    package_version = package['version']
                    vulnerabilities = package['vulnerabilities']
                    for vuln in vulnerabilities:
                        vuln_name = vuln.get('name')
                        vuln_severity = vuln.get('severity')
                        vuln_fixed_version = vuln.get('fixedVersion')
                        vuln_source = vuln.get('source')
                        if vuln.get('description'):
                            vuln_description = vuln.get('description')
                        else:
                            vuln_description = ''
                        vuln_score = vuln.get('score')
                        vuln_exploitability_score = vuln.get('exploitabilityScore')
                        vuln_cvss3_metrics = vuln.get('cvssV3Metrics')
                        vuln_cvss2_metrics = vuln.get('cvssV2Metrics')
                        vuln_has_exploit = vuln.get('hasExploit')
                        vuln_has_cisa_kev_exploit = vuln['hasCisaKevExploit']
                        vuln_has_cisa_kev_release_date = vuln['cisaKevReleaseDate']
                        vuln_has_cisa_kev_due_date = vuln['cisaKevDueDate']
                        vuln_epss_probability = vuln['epssProbability']
                        vuln_epss_percentile = vuln['epssPercentile']
                        vuln_epss_severity = vuln['epssSeverity']
                        vuln_publish_date = vuln['publishDate']
                        vuln_fix_publish_date = vuln['fixPublishDate']
                        vuln_grace_period_end = vuln['gracePeriodEnd']
                        vuln_grace_period_remaining_hours = vuln['gracePeriodRemainingHours']
                        vuln_failed_policy_matches = vuln['failedPolicyMatches']

                        findings.append([package_name, 
                                    package_version, 
                                    vuln_name, 
                                    vuln_severity, 
                                    vuln_fixed_version, 
                                    vuln_source, 
                                    vuln_description, 
                                    vuln_score, 
                                    vuln_exploitability_score,
                                    vuln_cvss3_metrics,
                                    vuln_cvss2_metrics,
                                    vuln_has_exploit,
                                    vuln_has_cisa_kev_exploit,
                                    vuln_has_cisa_kev_release_date,
                                    vuln_has_cisa_kev_due_date,
                                    vuln_epss_probability,
                                    vuln_epss_percentile,
                                    vuln_epss_severity,
                                    vuln_publish_date,
                                    vuln_fix_publish_date,
                                    vuln_grace_period_end,
                                    vuln_grace_period_remaining_hours,
                                    vuln_failed_policy_matches]
                                    )
                        forDefectDojo.append(
                            Finding(
                                title=vuln_name,
                                description=vuln_description,
                                severity=vuln_severity.lower().capitalize(),
                                static_finding=False,
                                dynamic_finding=True,
                                test=test,
                            )
                        )                  
                return forDefectDojo                
            else:
                print("[-] No isInstance of toJson dict")

    
