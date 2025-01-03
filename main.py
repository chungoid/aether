import asyncio
from core.scanmanager import ScanManager
from core.workflowmanager import WorkflowManager
from utils.stager import create_dir_structure, determine_target
from config.config import RESULTS_DIR


async def main():
    """
    Main entry point for initializing and executing the workflow.
    """
    print("Initializing Workflow...")

    # 1: Create directories
    create_dir_structure()

    # 2: Initialize Targets
    try:
        print("Determining targets...")
        targets = determine_target()  # template here
        if not targets:
            print("No targets selected. Exiting.")
            return
        print(f"Targets determined: {targets}")
    except Exception as e:
        print(f"Error determining targets: {e}")
        return

    # 3: Initialize ScanManager
    print("Initializing ScanManager...")
    scan_manager_instance = ScanManager()

    # 4: Initialize WorkflowManager
    print("Initializing WorkflowManager...")
    workflow_manager_instance = WorkflowManager(
        scan_manager_instance=scan_manager_instance,
        workflow_targets=targets,
        results_dir=RESULTS_DIR
    )

    # 4: Execute
    print("Executing workflow...")
    try:
        await workflow_manager_instance.execute_workflow()
        print("Workflow execution completed.")
    except Exception as e:
        print(f"Workflow execution failed: {e}")


if __name__ == "__main__":
    asyncio.run(main())
