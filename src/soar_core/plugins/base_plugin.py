from abc import ABC, abstractmethod

class BaseActionPlugin(ABC):
    """
    Abstract base class for all SOAR Agent Communication Integrations.
    Enforces standard execution and error-handling patterns.
    """
    
    @property
    @abstractmethod
    def plugin_name(self) -> str:
        pass

    @abstractmethod
    def execute_action(self, command: str, parameters: dict) -> dict:
        """
        Translates the playbook command into the specific vendor REST API payload.
        Returns a standardized dictionary with execution results.
        """
        pass
