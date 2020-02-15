using System;
using System.Runtime.Serialization;

namespace FlightProject.Exceptions
{
    [Serializable]
    public class NullResultException : Exception
    {
        internal NullResultException()
        {
        }

        internal NullResultException(string message) : base(message)
        {
        }

        internal NullResultException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected NullResultException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}