"""
YARA Cryptex - Iterative SDLC Controller
Manages the complete SDLC cycle with iterative improvements
"""

import asyncio
import json
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
import sys
from pathlib import Path

# Add parent directory to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(Path(__file__).parent))

try:
    from sdlc.ua_testing_framework import UATestSuite, InteractionLogger
    from sdlc.security_audit import SecurityAuditor
    from sdlc.code_simplification import CodeSimplifier
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure you're running from the project root")
    sys.exit(1)

class SDLCCycle:
    """Complete SDLC cycle manager"""
    
    def __init__(self, project_root: str = "."):
        self.project_root = Path(project_root)
        self.cycle_log = []
        self.current_cycle = 0
        
        self.setup_logging()
        
    def setup_logging(self):
        """Setup SDLC logging"""
        log_dir = self.project_root / "sdlc" / "cycles"
        log_dir.mkdir(parents=True, exist_ok=True)
        
        log_file = log_dir / f"sdlc_cycle_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        
        self.logger = logging.getLogger('SDLC')
    
    async def start_cycle(self):
        """Start a new SDLC cycle"""
        self.current_cycle += 1
        cycle_start = datetime.now()
        
        self.logger.info("=" * 80)
        self.logger.info(f"Starting SDLC Cycle #{self.current_cycle}")
        self.logger.info("=" * 80)
        
        cycle_data = {
            'cycle_number': self.current_cycle,
            'start_time': cycle_start.isoformat(),
            'steps': []
        }
        
        # Step 1: Security Audit
        self.logger.info("Step 1: Security Audit")
        try:
            auditor = SecurityAuditor(str(self.project_root))
            audit_report = auditor.run_full_audit()
            cycle_data['steps'].append({
                'step': 'security_audit',
                'status': 'completed',
                'report': str(audit_report)
            })
        except Exception as e:
            self.logger.error(f"Security audit failed: {e}")
            cycle_data['steps'].append({
                'step': 'security_audit',
                'status': 'failed',
                'error': str(e)
            })
        
        # Step 2: Code Simplification
        self.logger.info("Step 2: Code Simplification Analysis")
        try:
            simplifier = CodeSimplifier(str(self.project_root))
            simplification_report = simplifier.run_full_analysis()
            cycle_data['steps'].append({
                'step': 'code_simplification',
                'status': 'completed',
                'report': str(simplification_report)
            })
        except Exception as e:
            self.logger.error(f"Code simplification failed: {e}")
            cycle_data['steps'].append({
                'step': 'code_simplification',
                'status': 'failed',
                'error': str(e)
            })
        
        # Step 3: Build System
        self.logger.info("Step 3: Build System")
        try:
            build_result = self.build_system()
            cycle_data['steps'].append({
                'step': 'build',
                'status': 'completed' if build_result else 'failed',
                'result': build_result
            })
        except Exception as e:
            self.logger.error(f"Build failed: {e}")
            cycle_data['steps'].append({
                'step': 'build',
                'status': 'failed',
                'error': str(e)
            })
        
        # Step 4: Start Services
        self.logger.info("Step 4: Start Services")
        try:
            services_started = await self.start_services()
            cycle_data['steps'].append({
                'step': 'start_services',
                'status': 'completed' if services_started else 'failed',
                'services': services_started
            })
        except Exception as e:
            self.logger.error(f"Service startup failed: {e}")
            cycle_data['steps'].append({
                'step': 'start_services',
                'status': 'failed',
                'error': str(e)
            })
        
        # Step 5: UA Testing
        self.logger.info("Step 5: UA Testing")
        try:
            await self.run_ua_tests()
            cycle_data['steps'].append({
                'step': 'ua_testing',
                'status': 'completed'
            })
        except Exception as e:
            self.logger.error(f"UA testing failed: {e}")
            cycle_data['steps'].append({
                'step': 'ua_testing',
                'status': 'failed',
                'error': str(e)
            })
        
        # Step 6: Generate Report
        cycle_data['end_time'] = datetime.now().isoformat()
        cycle_data['duration'] = (datetime.now() - cycle_start).total_seconds()
        
        self.cycle_log.append(cycle_data)
        self.save_cycle_report(cycle_data)
        
        self.logger.info("=" * 80)
        self.logger.info(f"SDLC Cycle #{self.current_cycle} Complete")
        self.logger.info("=" * 80)
        
        return cycle_data
    
    def build_system(self) -> bool:
        """Build the system"""
        try:
            result = subprocess.run(
                ['cargo', 'build', '--release', '--workspace'],
                cwd=self.project_root / "rust",
                capture_output=True,
                text=True,
                timeout=600
            )
            
            if result.returncode == 0:
                self.logger.info("✅ Build successful")
                return True
            else:
                self.logger.error(f"❌ Build failed: {result.stderr}")
                return False
        except Exception as e:
            self.logger.error(f"Build error: {e}")
            return False
    
    async def start_services(self) -> Dict:
        """Start required services"""
        services = {}
        
        # Start API server
        try:
            api_process = subprocess.Popen(
                ['rust/cryptex-api/target/release/cryptex-api.exe'],
                cwd=self.project_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            services['api_server'] = {
                'pid': api_process.pid,
                'status': 'started'
            }
            self.logger.info(f"✅ API server started (PID: {api_process.pid})")
            
            # Wait for server to be ready
            await asyncio.sleep(5)
            
        except Exception as e:
            self.logger.error(f"Failed to start API server: {e}")
            services['api_server'] = {'status': 'failed', 'error': str(e)}
        
        return services
    
    async def run_ua_tests(self):
        """Run UA test suite"""
        try:
            suite = UATestSuite()
            await suite.run_complete_test_suite()
            self.logger.info("✅ UA tests completed")
        except Exception as e:
            self.logger.error(f"UA tests failed: {e}")
            raise
    
    def save_cycle_report(self, cycle_data: Dict):
        """Save cycle report"""
        report_file = self.project_root / "sdlc" / "cycles" / f"cycle_{self.current_cycle}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(report_file, 'w') as f:
            json.dump(cycle_data, f, indent=2)
        
        self.logger.info(f"Cycle report saved: {report_file}")
    
    async def run_iterative_cycles(self, num_cycles: int = 1):
        """Run multiple SDLC cycles"""
        self.logger.info(f"Starting {num_cycles} iterative SDLC cycles...")
        
        for i in range(num_cycles):
            await self.start_cycle()
            
            if i < num_cycles - 1:
                self.logger.info(f"Waiting before next cycle...")
                await asyncio.sleep(10)
        
        # Generate summary
        self.generate_summary()
    
    def generate_summary(self):
        """Generate SDLC summary"""
        summary = {
            'total_cycles': len(self.cycle_log),
            'cycles': self.cycle_log,
            'summary': {
                'security_audits': sum(1 for c in self.cycle_log if any(s['step'] == 'security_audit' and s['status'] == 'completed' for s in c['steps'])),
                'code_simplifications': sum(1 for c in self.cycle_log if any(s['step'] == 'code_simplification' and s['status'] == 'completed' for s in c['steps'])),
                'builds': sum(1 for c in self.cycle_log if any(s['step'] == 'build' and s['status'] == 'completed' for s in c['steps'])),
                'ua_tests': sum(1 for c in self.cycle_log if any(s['step'] == 'ua_testing' and s['status'] == 'completed' for s in c['steps']))
            }
        }
        
        summary_file = self.project_root / "sdlc" / f"sdlc_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        self.logger.info(f"SDLC summary saved: {summary_file}")

async def main():
    """Main entry point"""
    sdlc = SDLCCycle()
    await sdlc.run_iterative_cycles(num_cycles=1)

if __name__ == "__main__":
    asyncio.run(main())

