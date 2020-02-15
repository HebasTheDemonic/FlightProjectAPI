using System;
using System.Runtime.Serialization;

namespace FlightProject.Exceptions
{
    [Serializable]
    public class UnauthorizedActionException : Exception
    {
        internal UnauthorizedActionException()
        {
        }

        internal UnauthorizedActionException(string message) : base(message)
        {
        }

        internal UnauthorizedActionException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected UnauthorizedActionException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}