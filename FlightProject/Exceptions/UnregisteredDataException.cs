using System;
using System.Runtime.Serialization;

namespace FlightProject.Exceptions
{
    [Serializable]
    public class UnregisteredDataException : Exception
    {
        internal UnregisteredDataException()
        {
        }

        internal UnregisteredDataException(string message) : base(message)
        {
        }

        internal UnregisteredDataException(string message, Exception innerException) : base(message, innerException)
        {
        }

        protected UnregisteredDataException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}