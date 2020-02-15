using System;
using System.Runtime.Serialization;

namespace FlightProject.Exceptions
{
    [Serializable]
    public class UnregisteredUserException : Exception
    {
        internal UnregisteredUserException()
        {
        }

        internal UnregisteredUserException(string message) : base(message)
        {
        }

        internal UnregisteredUserException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected UnregisteredUserException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}