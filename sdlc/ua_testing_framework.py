"""
YARA Cryptex - Comprehensive UA Testing Framework
Full interaction logging and iterative improvement cycle
"""

import asyncio
import json
import logging
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import TimeoutException, NoSuchElementException

class InteractionLogger:
    """Logs all UI interactions, clicks, commands, and system events"""
    
    def __init__(self, log_dir: str = "ua_logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Setup comprehensive logging
        self.setup_logging()
        
        # Interaction log
        self.interactions = []
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        
    def setup_logging(self):
        """Setup comprehensive logging system"""
        log_file = self.log_dir / f"ua_session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.DEBUG,
            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger('UA_Testing')
        self.logger.info(f"UA Testing session started: {self.session_id}")
        
    def log_interaction(self, interaction_type: str, element: str, action: str, 
                       details: Optional[Dict] = None, screenshot: Optional[str] = None):
        """Log any UI interaction"""
        interaction = {
            'timestamp': datetime.now().isoformat(),
            'type': interaction_type,
            'element': element,
            'action': action,
            'details': details or {},
            'screenshot': screenshot
        }
        
        self.interactions.append(interaction)
        self.logger.info(f"Interaction: {interaction_type} - {element} - {action}")
        
        # Save to JSON log
        log_file = self.log_dir / f"interactions_{self.session_id}.json"
        with open(log_file, 'w') as f:
            json.dump(self.interactions, f, indent=2)
    
    def log_command(self, command: str, output: str, exit_code: int):
        """Log command execution"""
        self.log_interaction(
            'command',
            'terminal',
            command,
            {
                'output': output,
                'exit_code': exit_code
            }
        )
    
    def log_api_call(self, method: str, endpoint: str, response: Dict, status_code: int):
        """Log API calls"""
        self.log_interaction(
            'api_call',
            endpoint,
            method,
            {
                'response': response,
                'status_code': status_code
            }
        )
    
    def save_session_report(self):
        """Save complete session report"""
        report = {
            'session_id': self.session_id,
            'start_time': self.interactions[0]['timestamp'] if self.interactions else None,
            'end_time': datetime.now().isoformat(),
            'total_interactions': len(self.interactions),
            'interactions': self.interactions
        }
        
        report_file = self.log_dir / f"session_report_{self.session_id}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Session report saved: {report_file}")

class UITester:
    """Comprehensive UI testing with full interaction logging"""
    
    def __init__(self, logger: InteractionLogger):
        self.logger = logger
        self.driver = None
        self.base_url = "http://localhost:5173"
        self.api_url = "http://localhost:3006"
        
    def setup_driver(self):
        """Setup Selenium WebDriver with logging"""
        chrome_options = Options()
        chrome_options.add_argument('--start-maximized')
        chrome_options.add_argument('--enable-logging')
        chrome_options.add_argument('--v=1')
        chrome_options.add_experimental_option('useAutomationExtension', False)
        chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
        
        # Enable performance logging
        chrome_options.set_capability('goog:loggingPrefs', {
            'performance': 'ALL',
            'browser': 'ALL'
        })
        
        try:
            self.driver = webdriver.Chrome(options=chrome_options)
            self.logger.log_interaction('system', 'browser', 'started', {
                'url': self.base_url
            })
            return True
        except Exception as e:
            self.logger.logger.error(f"Failed to start browser: {e}")
            return False
    
    def take_screenshot(self, name: str) -> str:
        """Take screenshot and save"""
        screenshot_dir = self.logger.log_dir / "screenshots"
        screenshot_dir.mkdir(exist_ok=True)
        
        screenshot_path = screenshot_dir / f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        self.driver.save_screenshot(str(screenshot_path))
        
        self.logger.log_interaction('screenshot', name, 'captured', {
            'path': str(screenshot_path)
        }, str(screenshot_path))
        
        return str(screenshot_path)
    
    def navigate_to(self, path: str):
        """Navigate to a page and log"""
        url = f"{self.base_url}{path}"
        self.driver.get(url)
        
        self.logger.log_interaction('navigation', path, 'navigated', {
            'url': url,
            'title': self.driver.title
        })
        
        self.take_screenshot(f"page_{path.replace('/', '_')}")
        time.sleep(2)  # Wait for page load
    
    def click_element(self, by: By, value: str, element_name: str):
        """Click element and log"""
        try:
            element = WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((by, value))
            )
            
            # Scroll into view
            self.driver.execute_script("arguments[0].scrollIntoView(true);", element)
            time.sleep(0.5)
            
            # Take screenshot before click
            self.take_screenshot(f"before_click_{element_name}")
            
            element.click()
            
            self.logger.log_interaction('click', element_name, 'clicked', {
                'selector': value,
                'tag': element.tag_name,
                'text': element.text[:100] if element.text else None
            })
            
            time.sleep(1)  # Wait for action
            
            # Take screenshot after click
            self.take_screenshot(f"after_click_{element_name}")
            
            return True
        except (TimeoutException, NoSuchElementException) as e:
            self.logger.logger.error(f"Failed to click {element_name}: {e}")
            self.take_screenshot(f"error_click_{element_name}")
            return False
    
    def type_text(self, by: By, value: str, text: str, element_name: str):
        """Type text and log"""
        try:
            element = WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((by, value))
            )
            
            element.clear()
            element.send_keys(text)
            
            self.logger.log_interaction('type', element_name, 'typed', {
                'selector': value,
                'text': text[:100]
            })
            
            time.sleep(0.5)
            return True
        except (TimeoutException, NoSuchElementException) as e:
            self.logger.logger.error(f"Failed to type in {element_name}: {e}")
            return False
    
    def verify_element_present(self, by: By, value: str, element_name: str) -> bool:
        """Verify element is present"""
        try:
            element = WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((by, value))
            )
            
            self.logger.log_interaction('verify', element_name, 'present', {
                'selector': value,
                'visible': element.is_displayed()
            })
            
            return True
        except (TimeoutException, NoSuchElementException):
            self.logger.log_interaction('verify', element_name, 'missing', {
                'selector': value
            })
            return False
    
    def get_page_console_logs(self):
        """Get browser console logs"""
        try:
            logs = self.driver.get_log('browser')
            for log in logs:
                self.logger.log_interaction('console', 'browser', log['level'], {
                    'message': log['message'],
                    'timestamp': log['timestamp']
                })
            return logs
        except Exception as e:
            self.logger.logger.error(f"Failed to get console logs: {e}")
            return []
    
    def cleanup(self):
        """Cleanup browser"""
        if self.driver:
            self.driver.quit()
            self.logger.log_interaction('system', 'browser', 'closed', {})

class UATestSuite:
    """Complete UA test suite with iterative improvement"""
    
    def __init__(self):
        self.logger = InteractionLogger()
        self.ui_tester = UITester(self.logger)
        self.test_results = []
        
    async def test_api_server(self):
        """Test API server endpoints"""
        self.logger.logger.info("Testing API server...")
        
        endpoints = [
            '/api/v2/yara/cryptex/stats',
            '/api/v2/yara/cryptex/entries',
            '/api/v2/yara/cryptex/search?query=initialize',
            '/api/v2/yara/cryptex/lookup?symbol=yr_initialize'
        ]
        
        for endpoint in endpoints:
            try:
                response = requests.get(f"{self.ui_tester.api_url}{endpoint}", timeout=5)
                self.logger.log_api_call('GET', endpoint, response.json(), response.status_code)
                
                if response.status_code == 200:
                    self.logger.logger.info(f"✅ {endpoint} - OK")
                else:
                    self.logger.logger.warning(f"⚠️ {endpoint} - {response.status_code}")
            except Exception as e:
                self.logger.logger.error(f"❌ {endpoint} - {e}")
    
    def test_cryptex_dictionary_page(self):
        """Test Cryptex Dictionary Browser page"""
        self.logger.logger.info("Testing Cryptex Dictionary page...")
        
        self.ui_tester.navigate_to('/tools/yara/cryptex')
        
        # Verify page loaded
        assert self.ui_tester.verify_element_present(By.TAG_NAME, 'h1', 'page_title')
        
        # Test search functionality
        search_selectors = [
            ('input[type="text"]', 'search_input'),
            ('input[placeholder*="Search"]', 'search_placeholder'),
        ]
        
        for selector, name in search_selectors:
            if self.ui_tester.verify_element_present(By.CSS_SELECTOR, selector, name):
                self.ui_tester.type_text(By.CSS_SELECTOR, selector, 'initialize', name)
                time.sleep(2)
                break
        
        # Get console logs
        self.ui_tester.get_page_console_logs()
        
        self.logger.logger.info("✅ Cryptex Dictionary page tested")
    
    def test_feed_scanner_page(self):
        """Test Feed Scanner page"""
        self.logger.logger.info("Testing Feed Scanner page...")
        
        self.ui_tester.navigate_to('/tools/yara/feed')
        
        # Verify page loaded
        assert self.ui_tester.verify_element_present(By.TAG_NAME, 'h1', 'page_title')
        
        # Look for scan button
        button_selectors = [
            ('button', 'scan_button'),
            ('button[type="button"]', 'button_element'),
            ('*[class*="button"]', 'button_class'),
        ]
        
        for selector, name in button_selectors:
            try:
                if self.ui_tester.click_element(By.CSS_SELECTOR, selector, name):
                    break
            except:
                continue
        
        self.ui_tester.get_page_console_logs()
        
        self.logger.logger.info("✅ Feed Scanner page tested")
    
    def test_yara_scanner_page(self):
        """Test YARA Scanner page"""
        self.logger.logger.info("Testing YARA Scanner page...")
        
        self.ui_tester.navigate_to('/tools/yara/scan')
        
        # Verify page loaded
        assert self.ui_tester.verify_element_present(By.TAG_NAME, 'h1', 'page_title')
        
        # Look for file input or drag-drop area
        input_selectors = [
            ('input[type="file"]', 'file_input'),
            ('*[class*="drop"]', 'drop_zone'),
            ('*[class*="upload"]', 'upload_area'),
        ]
        
        for selector, name in input_selectors:
            if self.ui_tester.verify_element_present(By.CSS_SELECTOR, selector, name):
                break
        
        self.ui_tester.get_page_console_logs()
        
        self.logger.logger.info("✅ YARA Scanner page tested")
    
    async def run_complete_test_suite(self):
        """Run complete UA test suite"""
        self.logger.logger.info("=" * 60)
        self.logger.logger.info("Starting Complete UA Test Suite")
        self.logger.logger.info("=" * 60)
        
        # Setup browser
        if not self.ui_tester.setup_driver():
            self.logger.logger.error("Failed to setup browser")
            return
        
        try:
            # Test API server
            await self.test_api_server()
            
            # Test UI pages
            self.test_cryptex_dictionary_page()
            time.sleep(2)
            
            self.test_feed_scanner_page()
            time.sleep(2)
            
            self.test_yara_scanner_page()
            time.sleep(2)
            
            # Final screenshot
            self.ui_tester.take_screenshot("final_state")
            
        finally:
            self.ui_tester.cleanup()
            self.logger.save_session_report()
            
        self.logger.logger.info("=" * 60)
        self.logger.logger.info("UA Test Suite Complete")
        self.logger.logger.info("=" * 60)

async def main():
    """Main entry point"""
    suite = UATestSuite()
    await suite.run_complete_test_suite()

if __name__ == "__main__":
    asyncio.run(main())

