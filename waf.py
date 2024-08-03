from wafw00f.main import WAFW00F

class Waf_Detect:
    def __init__(self, url):
        self.url = url

    def waf_detect(self):
        try:
            wafw00f = WAFW00F(self.url)
            result = wafw00f.identwaf()
            if result:
                result = result[0].lower()
            else:
                return "No WAF detected"
            
            wafs = self.fetch_names('waf_list.txt')
            for waf in wafs:
                if waf in result:
                    return waf
            
            return "WAF detected but not in the list"
        
        except Exception as e:
            return f"An error occurred: {str(e)}"

    @staticmethod
    def fetch_names(filename):
        try:
            with open(filename, 'r') as waf_list:
                return [waf.strip().lower() for waf in waf_list.readlines()]
        except FileNotFoundError:
            return f"File {filename} not found."
        except Exception as e:
            return f"An error occurred while reading the file: {str(e)}"

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python waf.py <url> <waf_list_file>")
        sys.exit(1)

    url = sys.argv[1]
    waf_list_file = sys.argv[2]

    detector = Waf_Detect(url)
    waf_name = detector.waf_detect()
    print(f"Detected WAF: {waf_name}")
