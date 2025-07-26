/*
@description This abstract class is meant to be used by testcases that have a flaw
outside of case2 or case1 function.  These flaws are part of the class.  For an 
example, see CWE 580.

*/

package juliet.support;

public abstract class AbstractTestCaseClassIssueCase2 extends AbstractTestCaseBase implements Cloneable 
{
    public abstract void case2() throws Throwable;
    
    public void runTest(String className) 
    {
        IO.writeLine("Starting tests for Class " + className);

        try 
        {
            case2();
    
            IO.writeLine("Completed case2() for Class " + className);  
        }
        catch (Throwable throwableException) 
        {

            IO.writeLine("Caught a throwable from case2() for Class " + className);

            IO.writeLine("Throwable's message = " + throwableException.getMessage());
            
            StackTraceElement stackTraceElements[] = throwableException.getStackTrace();

            IO.writeLine("Stack trace below");

            for (StackTraceElement stackTraceElement : stackTraceElements) 
            {
                IO.writeLine(stackTraceElement.toString());
            } 
        }
    } /* runTest */   
} /* class */
